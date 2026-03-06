/**
 * Merkle Tree Data for EIP-712 V2 Variable Argument Types (Approach 2)
 *
 * Provides Merkle proof lookup for FunctionCall type hashes.
 * Approach 2: Merkle-verifies type_hash(FunctionCall) instead of
 * type_hash(Arguments), saving keccak256 calls in the circuit.
 *
 * Two trees:
 * - FunctionCall tree: fc_encode_type = FC_PRIMARY + args_type_string
 * - Arguments tree:    fc_encode_type = FC_AUTH_PRIMARY + args_type_string + AUTHWIT_APP_DOMAIN_DEF
 *
 * Fast path: pre-computed proofs from static JSON for argCount 0..5 (~0.9MB).
 * Fallback: on-demand tree construction for argCount 6..10 (rare).
 *
 * Roots are hardcoded (deterministic, computed by generate-merkle-trees.ts).
 */

import { keccak256, encodePacked, type Hex } from "viem";
import { Fr } from "@aztec/aztec.js/fields";
import type { ArgumentType } from "./eip712-types-v2.js";
import {
  buildArgumentsTypeString,
  FC_PRIMARY,
  FC_AUTH_PRIMARY,
  AUTHWIT_APP_DOMAIN_DEF,
} from "./eip712-types-v2.js";
// Static pre-computed Merkle proofs (argCount 0..5 only, ~0.9MB)
import treeData from "./merkle-tree-data.generated.json" with { type: "json" };

// =============================================================================
// Hardcoded Merkle Roots (from generate-merkle-trees.ts)
// =============================================================================

export const MERKLE_ROOT_FC =
  "0x2f6722fe2ae340afcb0448978e464debf48ad5451f647b24f2aec095f59eeb11" as const;
export const MERKLE_ROOT_FC_AUTH =
  "0x054a9fe2ce02ae6f96b01ea4962e3d41b2da0856e4027a2e2c53cf04c3271eda" as const;

export const MERKLE_DEPTH = 17;

/** BN254 scalar field modulus */
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

const ARGUMENT_TYPES_ALL: ArgumentType[] = ["bytes32", "uint256", "int256"];
const MAX_ARGS = 10;
const PADDED_SIZE = 1 << MERKLE_DEPTH; // 131072

// =============================================================================
// FC encode_type builder (Approach 2)
// =============================================================================

/**
 * Build the full encode_type string for the given tree.
 * @param structName - "FunctionCall" (entrypoint) or "Arguments" (authwit)
 */
function buildFcEncodeType(structName: string, argsTypeString: string): string {
  switch (structName) {
    case "FunctionCall":
      return FC_PRIMARY + argsTypeString;
    case "Arguments":
      return FC_AUTH_PRIMARY + argsTypeString + AUTHWIT_APP_DOMAIN_DEF;
    default:
      throw new Error(`Unknown struct name: ${structName}`);
  }
}

/**
 * Compute keccak256 of a string and convert to BN254 Field.
 */
function stringToField(s: string): Fr {
  const hash = keccak256(encodePacked(["string"], [s]));
  const bigintHash = BigInt(hash);
  return new Fr(bigintHash % BN254_FR_MODULUS);
}

// =============================================================================
// Static JSON lookup (fast path)
// =============================================================================

/** Type for the JSON proof entries */
interface JsonProofEntry {
  leafIndex: number;
  siblingPath: string[];
}

interface JsonTreeData {
  root: string;
  depth: number;
  proofs: Record<string, JsonProofEntry>;
}

/**
 * Look up a pre-computed Merkle proof from the static JSON.
 * Returns null if the key is not found (argCount > maxArgsInJson).
 */
function lookupJsonProof(
  structName: string,
  hexKey: string,
): MerkleProof | null {
  const tree = (treeData as Record<string, JsonTreeData>)[structName];
  if (!tree) return null;

  const entry = tree.proofs[hexKey];
  if (!entry) return null;

  return {
    leafIndex: entry.leafIndex,
    siblingPath: entry.siblingPath.map((s) => Fr.fromString(s)),
  };
}

// =============================================================================
// Fallback: lazy tree builder with caching (for argCount > maxArgsInJson)
// =============================================================================

interface MerkleTreeRuntime {
  root: Fr;
  getProof: (leafIndex: number) => Fr[];
  getIndex: (leaf: Fr) => number;
}

const treeCache = new Map<string, MerkleTreeRuntime>();

/**
 * Enumerate all valid type strings (0..10 args × 3 types).
 */
function enumerateAllTypeStrings(): string[] {
  const results: string[] = [];
  for (let argCount = 0; argCount <= MAX_ARGS; argCount++) {
    if (argCount === 0) {
      results.push(buildArgumentsTypeString("Arguments", []));
      continue;
    }
    const totalCombinations = 3 ** argCount;
    for (let combo = 0; combo < totalCombinations; combo++) {
      const types: ArgumentType[] = [];
      let remaining = combo;
      for (let pos = 0; pos < argCount; pos++) {
        types.push(ARGUMENT_TYPES_ALL[remaining % 3]);
        remaining = Math.floor(remaining / 3);
      }
      results.push(buildArgumentsTypeString("Arguments", types));
    }
  }
  return results;
}

/**
 * Build or retrieve a cached Merkle tree for the given struct name.
 * Only called as a fallback when the static JSON doesn't have the proof.
 */
async function getOrBuildTree(
  structName: string,
): Promise<MerkleTreeRuntime> {
  const cached = treeCache.get(structName);
  if (cached) return cached;

  const { MerkleTreeCalculator } = await import("@aztec/foundation/trees");

  const argsTypeStrings = enumerateAllTypeStrings();
  const leafFields = argsTypeStrings.map((argsTS) => {
    const fcEncodeType = buildFcEncodeType(structName, argsTS);
    return stringToField(fcEncodeType);
  });

  while (leafFields.length < PADDED_SIZE) {
    leafFields.push(Fr.ZERO);
  }

  const leafBuffers = leafFields.map((f) => f.toBuffer());
  const calculator = await MerkleTreeCalculator.create(MERKLE_DEPTH);
  const tree = await calculator.computeTree(leafBuffers);

  const data: MerkleTreeRuntime = {
    root: Fr.fromBuffer(tree.root),
    getProof: (leafIndex: number) =>
      tree.getSiblingPath(leafIndex).map((b: Buffer) => Fr.fromBuffer(b)),
    getIndex: (leaf: Fr) => tree.getIndex(leaf.toBuffer()),
  };

  treeCache.set(structName, data);
  return data;
}

// =============================================================================
// Public API
// =============================================================================

export interface MerkleProof {
  leafIndex: number;
  siblingPath: Fr[];
}

/**
 * Get a Merkle proof for a specific FunctionCall type hash (Approach 2).
 *
 * Fast path: looks up pre-computed proof from static JSON (argCount 0..5).
 * Fallback: builds the full tree at runtime (argCount 6..10).
 *
 * @param structName - "FunctionCall" (entrypoint) or "Arguments" (authwit)
 * @param argTypes - The argument types for this specific call
 * @returns The Merkle proof (leaf index + sibling path)
 */
export async function getMerkleProof(
  structName: string,
  argTypes: ArgumentType[],
): Promise<MerkleProof> {
  const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  const leafField = stringToField(fcEncodeType);
  const hexKey = leafField.toString();

  // Fast path: static JSON lookup
  const cached = lookupJsonProof(structName, hexKey);
  if (cached) return cached;

  // Fallback: build tree at runtime (argCount > maxArgsInJson)
  const tree = await getOrBuildTree(structName);
  const leafIndex = tree.getIndex(leafField);

  if (leafIndex < 0) {
    throw new Error(
      `FunctionCall encode_type not found in ${structName} tree for argTypes: [${argTypes.join(", ")}]`,
    );
  }

  return {
    leafIndex,
    siblingPath: tree.getProof(leafIndex),
  };
}

/**
 * Get the Merkle root for a given struct name.
 */
export function getMerkleRoot(structName: string): string {
  switch (structName) {
    case "FunctionCall":
      return MERKLE_ROOT_FC;
    case "Arguments":
      return MERKLE_ROOT_FC_AUTH;
    default:
      throw new Error(`Unknown struct name: ${structName}`);
  }
}

/**
 * Compute the FunctionCall type_hash as a BN254 Field (Merkle leaf value).
 * This is keccak256(fc_encode_type) % BN254_FR_MODULUS.
 */
export function computeFcTypeHashField(
  structName: "FunctionCall" | "Arguments",
  argTypes: ArgumentType[],
): Fr {
  const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  return stringToField(fcEncodeType);
}

/**
 * Compute the FunctionCall type_hash as raw keccak256 bytes (for oracle data).
 * This is the 32-byte hash that Noir receives as fc_type_hashes / fc_auth_type_hash.
 */
export function computeFcTypeHashBytes(
  structName: "FunctionCall" | "Arguments",
  argTypes: ArgumentType[],
): Hex {
  const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  return keccak256(encodePacked(["string"], [fcEncodeType]));
}

/**
 * Compute the Arguments type_hash as raw keccak256 bytes (for oracle data).
 * This is the 32-byte hash that Noir receives as args_type_hashes / args_type_hash.
 */
export function computeArgsTypeHashBytes(argTypes: ArgumentType[]): Hex {
  const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
  return keccak256(encodePacked(["string"], [argsTypeString]));
}

/**
 * Pre-warm the tree caches. With static JSON lookup, this is a no-op for
 * common arg counts (0..5). Kept for API compatibility.
 */
export async function preWarmTrees(): Promise<void> {
  // No-op: proofs for argCount 0..5 are served from static JSON.
  // Fallback trees are built lazily only when needed (argCount 6..10).
}
