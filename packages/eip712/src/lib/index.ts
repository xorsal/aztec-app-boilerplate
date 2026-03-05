/**
 * EIP-712 Module for Aztec Account Contracts
 *
 * Provides human-readable transaction signing via MetaMask.
 */

export * from "./eip712-types";
export * from "./eip712-encoder";
export * from "./eip712-account";

// V2 - Variable argument types
export * from "./eip712-types-v2.js";
export * from "./eip712-encoder-v2.js";
export * from "./eip712-account-v2.js";
export {
  getMerkleProof,
  getMerkleRoot,
  computeTypeHashField,
  computeFcTypeHashField,
  computeFcTypeHashBytes,
  computeArgsTypeHashBytes,
  preWarmTrees,
  MERKLE_ROOT_ARGUMENTS,
  MERKLE_ROOT_ARGUMENTS1,
  MERKLE_ROOT_ARGUMENTS2,
  type MerkleProof,
} from "./merkle-tree-data.js";
