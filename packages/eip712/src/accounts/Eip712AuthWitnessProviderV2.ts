/**
 * EIP-712 V2 Auth Witness Provider Types
 *
 * Type definitions for the V2 signing delegate with variable argument types.
 * V2 adds per-argument type annotations and Merkle proofs to the signing interface.
 */

import type { ContractArtifact } from "@aztec/aztec.js/abi";
import type { AztecAddress } from "@aztec/aztec.js/addresses";
import type { FunctionCall } from "@aztec/stdlib/abi";
import type { Capsule } from "@aztec/stdlib/tx";

/**
 * V2 Signing delegate for EIP-712 entrypoint capsule creation with variable arg types.
 *
 * The entrypoint calls this delegate during payload construction to create
 * the EIP-712 capsule containing signature, witness data, and Merkle proofs
 * for the variable argument type whitelist.
 */
export interface Eip712SigningDelegateV2 {
  /**
   * Register a contract artifact for automatic function signature resolution.
   */
  registerContractArtifact(
    address: AztecAddress,
    artifact: ContractArtifact,
  ): void;

  /**
   * Creates a V2 EIP-712 witness capsule for the given function calls.
   * Includes per-argument type annotations and Merkle proofs.
   *
   * @param calls - Raw SDK FunctionCall objects from the ExecutionPayload
   * @param txNonce - Transaction nonce
   * @param contractAddress - The EIP-712 account contract address (capsule target)
   * @returns The capsule containing EIP-712 signature, witness data, and Merkle proofs
   */
  createWitnessCapsuleV2(
    calls: FunctionCall[],
    txNonce: bigint,
    contractAddress: AztecAddress,
  ): Promise<Capsule>;
}
