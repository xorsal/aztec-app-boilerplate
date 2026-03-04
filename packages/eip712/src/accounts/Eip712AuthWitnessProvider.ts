/**
 * EIP-712 Auth Witness Provider Types
 *
 * Type definitions for EIP-712 signing delegate and auth witness providers.
 *
 * EIP-712 provides human-readable function names and arguments in MetaMask.
 * Two modes of operation:
 * 1. Entrypoint Authorization (AppPayload): Signs batch of up to 5 function calls
 * 2. Individual Authwit: Signs single function call for approve/transfer patterns
 *
 * The signed data is delivered to the Noir contract via Capsule (oracle injection),
 * not via the standard AuthWitness mechanism. The signing delegate is called by the
 * entrypoint during payload construction — no side-channel needed.
 */

import type { ContractArtifact } from "@aztec/aztec.js/abi";
import type { AztecAddress } from "@aztec/aztec.js/addresses";
import type { FunctionCall } from "@aztec/stdlib/abi";
import type { Capsule } from "@aztec/stdlib/tx";
import type { Hex, WalletClient } from "viem";

/**
 * Interface for PXE capsule injection
 */
export interface CapsuleInjector {
  pushCapsule(capsule: Capsule): Promise<void>;
}

/**
 * Options for creating an Eip712AuthWitnessProvider
 */
export interface Eip712AuthWitnessProviderOptions {
  /** Viem wallet client connected to MetaMask */
  walletClient: WalletClient;
  /** The connected Ethereum address */
  account: Hex;
  /** The account contract address */
  contractAddress: AztecAddress;
  /** Injector for pushing capsules to PXE (typically PXE.pushCapsule) */
  capsuleInjector: CapsuleInjector;
  /** Optional chain ID (defaults to 31337 for sandbox) */
  chainId?: bigint;
  /** Optional verifying contract address */
  verifyingContract?: Hex;
  /** Enable debug logging to see typed data sent to MetaMask */
  debug?: boolean;
}

/**
 * Signing delegate for EIP-712 entrypoint capsule creation.
 *
 * The entrypoint calls this delegate during payload construction to create
 * the EIP-712 capsule containing the signature and witness data. This replaces
 * the former PendingTxContext side-channel pattern.
 *
 * Implementations resolve function signatures from registered contract
 * artifacts, keeping the entrypoint clean.
 */
export interface Eip712SigningDelegate {
  /**
   * Register a contract artifact for automatic function signature resolution.
   * When createWitnessCapsule receives calls targeting this address, the delegate
   * looks up the function by call.name in the artifact to build the EIP-712 signature.
   *
   * @param address - The deployed contract address
   * @param artifact - The contract artifact containing function definitions
   */
  registerContractArtifact(
    address: AztecAddress,
    artifact: ContractArtifact,
  ): void;

  /**
   * Creates an EIP-712 witness capsule for the given function calls.
   *
   * @param calls - Raw SDK FunctionCall objects from the ExecutionPayload
   * @param txNonce - Transaction nonce (used in both capsule and app payload)
   * @param contractAddress - The EIP-712 account contract address (capsule target)
   * @returns The capsule containing EIP-712 signature and witness data
   */
  createWitnessCapsule(
    calls: FunctionCall[],
    txNonce: bigint,
    contractAddress: AztecAddress,
  ): Promise<Capsule>;
}
