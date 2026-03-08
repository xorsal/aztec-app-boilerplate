/**
 * Merkle Tree Data for EIP-712 V2 Variable Argument Types (Approach 2)
 *
 * Provides Merkle proof lookup for FunctionCall type hashes.
 * Approach 2: Merkle-verifies type_hash(FunctionCall{N}) instead of
 * type_hash(Arguments{N}), saving keccak256 calls in the circuit.
 *
 * Five trees:
 * - FunctionCall1..4 trees: fc_encode_type = FC_PRIMARIES[N] + args_type_string
 * - Arguments tree:         fc_encode_type = FC_AUTH_PRIMARY + args_type_string + AUTHWIT_APP_DOMAIN_DEF
 *
 * All proofs are pre-computed in static JSON (MAX_ARGS=5, 364 leaves per tree, depth 9).
 * Roots are hardcoded (deterministic, computed by generate-merkle-trees.ts).
 */

import { keccak256, encodePacked, type Hex } from "viem";
import { Fr } from "@aztec/aztec.js/fields";
import type { ArgumentType } from "./eip712-types-v2.js";
import {
  buildArgumentsTypeString,
  FC_PRIMARIES,
  FC_AUTH_PRIMARY,
  AUTHWIT_APP_DOMAIN_DEF,
} from "./eip712-types-v2.js";
import treeData from "./merkle-tree-data.generated.json" with { type: "json" };

// =============================================================================
// Hardcoded Merkle Roots (from generate-merkle-trees.ts)
// =============================================================================

export const MERKLE_ROOT_FC_1 =
  "0x0633271a5313ed24c0224cb0c3b1c473a393aa19c1a2c085b816049fb0664c72" as const;
export const MERKLE_ROOT_FC_2 =
  "0x1fff6ffbccdd0193cd86f012093853422edad7dab5b6cc22d6c6b6d664151fe6" as const;
export const MERKLE_ROOT_FC_3 =
  "0x2c2ab955012fb60577f397a7cb81d49537ef371d368a42f3425d1944b0e4fa45" as const;
export const MERKLE_ROOT_FC_4 =
  "0x265613959ca7750afaa1fa7979a7ecdeed16fa1e9b437a5f86f576b99ab3bcf6" as const;
export const MERKLE_ROOT_FC_AUTH =
  "0x10ea5cfa7846f28e2c7d96cb47a4afcf26b710641d78e7aae894a04d53c2da7a" as const;

export const MERKLE_DEPTH = 9;

/** BN254 scalar field modulus */
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Derive the Arguments struct name from a tree struct name.
 * "FunctionCall1" → "Arguments1", "FunctionCall2" → "Arguments2", etc.
 * "Arguments" → "Arguments" (authwit)
 */
function getArgsStructName(structName: string): string {
  if (structName.startsWith("FunctionCall")) {
    return `Arguments${structName.replace("FunctionCall", "")}`;
  }
  return "Arguments";
}

// =============================================================================
// FC encode_type builder (Approach 2)
// =============================================================================

/**
 * Build the full encode_type string for the given tree.
 * @param structName - "FunctionCall1".."FunctionCall4" (entrypoint) or "Arguments" (authwit)
 */
function buildFcEncodeType(structName: string, argsTypeString: string): string {
  if (structName.startsWith("FunctionCall")) {
    const n = parseInt(structName.replace("FunctionCall", ""));
    return FC_PRIMARIES[n] + argsTypeString;
  }
  if (structName === "Arguments") {
    return FC_AUTH_PRIMARY + argsTypeString + AUTHWIT_APP_DOMAIN_DEF;
  }
  throw new Error(`Unknown struct name: ${structName}`);
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
// Public API
// =============================================================================

export interface MerkleProof {
  leafIndex: number;
  siblingPath: Fr[];
}

/**
 * Get a Merkle proof for a specific FunctionCall type hash (Approach 2).
 * All proofs are pre-computed in the static JSON (MAX_ARGS=5, 364 leaves).
 *
 * @param structName - "FunctionCall1".."FunctionCall4" (entrypoint) or "Arguments" (authwit)
 * @param argTypes - The argument types for this specific call
 * @returns The Merkle proof (leaf index + sibling path)
 */
export function getMerkleProof(
  structName: string,
  argTypes: ArgumentType[],
): MerkleProof {
  const argsStructName = getArgsStructName(structName);
  const argsTypeString = buildArgumentsTypeString(argsStructName, argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  const leafField = stringToField(fcEncodeType);
  const hexKey = leafField.toString();

  const proof = lookupJsonProof(structName, hexKey);
  if (!proof) {
    throw new Error(
      `FunctionCall encode_type not found in ${structName} tree for argTypes: [${argTypes.join(", ")}]`,
    );
  }

  return proof;
}

/**
 * Get the Merkle root for a given struct name.
 */
export function getMerkleRoot(structName: string): string {
  switch (structName) {
    case "FunctionCall1":
      return MERKLE_ROOT_FC_1;
    case "FunctionCall2":
      return MERKLE_ROOT_FC_2;
    case "FunctionCall3":
      return MERKLE_ROOT_FC_3;
    case "FunctionCall4":
      return MERKLE_ROOT_FC_4;
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
  structName: string,
  argTypes: ArgumentType[],
): Fr {
  const argsStructName = getArgsStructName(structName);
  const argsTypeString = buildArgumentsTypeString(argsStructName, argTypes);
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
  const argsStructName = getArgsStructName(structName);
  const argsTypeString = buildArgumentsTypeString(argsStructName, argTypes);
  const fcEncodeType = buildFcEncodeType(structName, argsTypeString);
  return keccak256(encodePacked(["string"], [fcEncodeType]));
}

/**
 * Compute the Arguments type_hash as raw keccak256 bytes (for oracle data).
 * This is the 32-byte hash that Noir receives as args_type_hashes / args_type_hash.
 *
 * @param slotNumber - 1-4 for entrypoint (Arguments1..4), 0 for authwit (Arguments)
 * @param argTypes - The argument types
 */
export function computeArgsTypeHashBytes(slotNumber: number, argTypes: ArgumentType[]): Hex {
  const structName = slotNumber === 0 ? "Arguments" : `Arguments${slotNumber}`;
  const argsTypeString = buildArgumentsTypeString(structName, argTypes);
  return keccak256(encodePacked(["string"], [argsTypeString]));
}

/**
 * Pre-warm the tree caches. No-op since all proofs are in static JSON.
 * Kept for API compatibility.
 */
export async function preWarmTrees(): Promise<void> {
  // No-op: all proofs are pre-computed in static JSON.
}
