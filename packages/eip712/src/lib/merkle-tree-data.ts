/**
 * Merkle Tree Data for EIP-712 V2 Variable Argument Types (Approach 2)
 *
 * Provides on-demand Merkle proof generation for FunctionCall type hashes.
 * Approach 2: Merkle-verifies type_hash(FunctionCall{N}) instead of
 * type_hash(Arguments{N}), saving 4 keccak256 calls in the circuit.
 *
 * Leaves are keccak256(fc_encode_type) % BN254_FR_MODULUS, where:
 * - Arguments1 tree: fc_encode_type = FC1_PRIMARY + args_type_string
 * - Arguments2 tree: fc_encode_type = FC2_PRIMARY + args_type_string
 * - Arguments tree:  fc_encode_type = FC_AUTH_PRIMARY + args_type_string + AUTHWIT_APP_DOMAIN_DEF
 *
 * Roots are hardcoded (deterministic, computed by generate-merkle-trees.ts).
 */

import { keccak256, encodePacked, type Hex } from "viem";
import { MerkleTreeCalculator } from "@aztec/foundation/trees";
import { Fr } from "@aztec/aztec.js/fields";
import type { ArgumentType } from "./eip712-types-v2.js";
import {
  buildArgumentsTypeString,
  FC1_PRIMARY,
  FC2_PRIMARY,
  FC_AUTH_PRIMARY,
  AUTHWIT_APP_DOMAIN_DEF,
} from "./eip712-types-v2.js";

// =============================================================================
// Hardcoded Merkle Roots (from generate-merkle-trees.ts)
// =============================================================================

export const MERKLE_ROOT_ARGUMENTS =
  "0x054a9fe2ce02ae6f96b01ea4962e3d41b2da0856e4027a2e2c53cf04c3271eda" as const;
export const MERKLE_ROOT_ARGUMENTS1 =
  "0x23807fde3749e9b5ddbc6c91886cc6e55280139ed5518a318fb21af017089c94" as const;
export const MERKLE_ROOT_ARGUMENTS2 =
  "0x1b95d5f26019d68281772cf97daae098abad03aff858c1790ec3082b717a0565" as const;

export const MERKLE_DEPTH = 17;

/** BN254 scalar field modulus */
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

const ARGUMENT_TYPES: ArgumentType[] = ["bytes32", "uint256", "int256"];
const MAX_ARGS = 10;
const PADDED_SIZE = 1 << MERKLE_DEPTH; // 131072

// =============================================================================
// FC encode_type builder (Approach 2)
// =============================================================================

/**
 * Build the full encode_type string for the FunctionCall struct
 * that references the given Arguments struct.
 */
function buildFcEncodeType(structName: string, argsTypeString: string): string {
  switch (structName) {
    case "Arguments1":
      return FC1_PRIMARY + argsTypeString;
    case "Arguments2":
      return FC2_PRIMARY + argsTypeString;
    case "Arguments":
      // FunctionCallAuthorization references Arguments + AuthwitAppDomain (sorted)
      return FC_AUTH_PRIMARY + argsTypeString + AUTHWIT_APP_DOMAIN_DEF;
    default:
      throw new Error(`Unknown struct name: ${structName}`);
  }
}

// =============================================================================
// Lazy tree builder with caching
// =============================================================================

interface MerkleTreeData {
  root: Fr;
  getProof: (leafIndex: number) => Fr[];
  getIndex: (leaf: Fr) => number;
}

const treeCache = new Map<string, MerkleTreeData>();

/**
 * Enumerate all valid type strings for a struct name (0..10 args × 3 types).
 */
function enumerateAllTypeStrings(structName: string): string[] {
  const results: string[] = [];
  for (let argCount = 0; argCount <= MAX_ARGS; argCount++) {
    if (argCount === 0) {
      results.push(buildArgumentsTypeString(structName, []));
      continue;
    }
    const totalCombinations = 3 ** argCount;
    for (let combo = 0; combo < totalCombinations; combo++) {
      const types: ArgumentType[] = [];
      let remaining = combo;
      for (let pos = 0; pos < argCount; pos++) {
        types.push(ARGUMENT_TYPES[remaining % 3]);
        remaining = Math.floor(remaining / 3);
      }
      results.push(buildArgumentsTypeString(structName, types));
    }
  }
  return results;
}

/**
 * Compute keccak256 of a string and convert to BN254 Field.
 */
function stringToField(s: string): Fr {
  const hash = keccak256(encodePacked(["string"], [s]));
  const bigintHash = BigInt(hash);
  return new Fr(bigintHash % BN254_FR_MODULUS);
}

/**
 * Build or retrieve a cached Merkle tree for the given struct name.
 * Approach 2: leaves are keccak256(fc_encode_type) % BN254.
 */
async function getOrBuildTree(structName: string): Promise<MerkleTreeData> {
  const cached = treeCache.get(structName);
  if (cached) return cached;

  // Enumerate all args type strings and convert to fc_encode_type leaves
  const argsTypeStrings = enumerateAllTypeStrings(structName);
  const leafFields = argsTypeStrings.map((argsTS) => {
    const fcEncodeType = buildFcEncodeType(structName, argsTS);
    return stringToField(fcEncodeType);
  });

  // Pad to power of 2
  while (leafFields.length < PADDED_SIZE) {
    leafFields.push(Fr.ZERO);
  }

  // Build tree
  const leafBuffers = leafFields.map((f) => f.toBuffer());
  const calculator = await MerkleTreeCalculator.create(MERKLE_DEPTH);
  const tree = await calculator.computeTree(leafBuffers);

  const data: MerkleTreeData = {
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
 * @param structName - "Arguments", "Arguments1", or "Arguments2"
 * @param argTypes - The argument types for this specific call
 * @returns The Merkle proof (leaf index + sibling path)
 */
export async function getMerkleProof(
  structName: string,
  argTypes: ArgumentType[],
): Promise<MerkleProof> {
  const tree = await getOrBuildTree(structName);
  const argsTypeString = buildArgumentsTypeString(structName, argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  const leafField = stringToField(fcEncodeType);
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
    case "Arguments":
      return MERKLE_ROOT_ARGUMENTS;
    case "Arguments1":
      return MERKLE_ROOT_ARGUMENTS1;
    case "Arguments2":
      return MERKLE_ROOT_ARGUMENTS2;
    default:
      throw new Error(`Unknown struct name: ${structName}`);
  }
}

/**
 * Compute the FunctionCall type_hash as a BN254 Field (Merkle leaf value).
 * This is keccak256(fc_encode_type) % BN254_FR_MODULUS.
 */
export function computeFcTypeHashField(
  structName: string,
  argTypes: ArgumentType[],
): Fr {
  const argsTypeString = buildArgumentsTypeString(structName, argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  return stringToField(fcEncodeType);
}

/**
 * Compute the FunctionCall type_hash as raw keccak256 bytes (for oracle data).
 * This is the 32-byte hash that Noir receives as fc_type_hashes / fc_auth_type_hash.
 */
export function computeFcTypeHashBytes(
  structName: string,
  argTypes: ArgumentType[],
): Hex {
  const argsTypeString = buildArgumentsTypeString(structName, argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  return keccak256(encodePacked(["string"], [fcEncodeType]));
}

/**
 * Compute the Arguments type_hash as raw keccak256 bytes (for oracle data).
 * This is the 32-byte hash that Noir receives as args_type_hashes / args_type_hash.
 */
export function computeArgsTypeHashBytes(
  structName: string,
  argTypes: ArgumentType[],
): Hex {
  const argsTypeString = buildArgumentsTypeString(structName, argTypes);
  return keccak256(encodePacked(["string"], [argsTypeString]));
}

/**
 * @deprecated Use computeFcTypeHashField instead (Approach 2)
 */
export function computeTypeHashField(
  structName: string,
  argTypes: ArgumentType[],
): Fr {
  return computeFcTypeHashField(structName, argTypes);
}

/**
 * Pre-warm the tree caches for all 3 struct names.
 * Call this during initialization if you want to avoid the latency of
 * building trees on the first proof request.
 */
export async function preWarmTrees(): Promise<void> {
  await Promise.all([
    getOrBuildTree("Arguments"),
    getOrBuildTree("Arguments1"),
    getOrBuildTree("Arguments2"),
  ]);
}
