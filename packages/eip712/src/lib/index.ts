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
  computeFcTypeHashField,
  computeFcTypeHashBytes,
  computeArgsTypeHashBytes,
  preWarmTrees,
  MERKLE_ROOT_FC,
  MERKLE_ROOT_FC_AUTH,
  type MerkleProof,
} from "./merkle-tree-data.js";
