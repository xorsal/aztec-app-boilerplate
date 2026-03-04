/**
 * EIP-712 Account Contract Implementation
 *
 * This AccountContract implementation uses EIP-712 typed data signing
 * for human-readable transaction authorization via MetaMask.
 *
 * Unlike standard ECDSA accounts that sign raw hashes, this account:
 * 1. Shows users readable function names and arguments in MetaMask
 * 2. Uses the EIP-712 capsule-based entrypoint for batched transactions
 * 3. Supports individual authwits for approve/transfer patterns
 */

import type { ContractArtifact } from "@aztec/aztec.js/abi";
import {
  type AccountContract,
  type Account,
  BaseAccount,
  type AuthWitnessProvider,
} from "@aztec/aztec.js/account";
import type { CompleteAddress } from "@aztec/aztec.js/addresses";
import { Eip712AccountEntrypoint } from "./Eip712AccountEntrypoint.js";
import type { Eip712SigningDelegate } from "./Eip712AuthWitnessProvider.js";
import { Eip712AccountContractArtifact } from "../artifacts.js";

/**
 * AccountContract implementation for EIP-712 accounts that use
 * typed data signing for human-readable authorization.
 *
 * This account contract:
 * 1. Takes the public key coordinates (x, y) during construction
 * 2. Delegates signing to an Eip712SigningDelegate via the entrypoint
 * 3. Shows human-readable function calls in MetaMask
 *
 * The Noir contract verifies EIP-712 typed data signatures:
 * - Builds EIP-712 domain separator with verifyingContract
 * - Computes typed data hash of function calls
 * - Verifies secp256k1 ECDSA signature
 */
export class Eip712AccountContract implements AccountContract {
  private readonly publicKeyX: Buffer;
  private readonly publicKeyY: Buffer;
  private readonly authWitnessProvider: AuthWitnessProvider;
  private readonly signingDelegate?: Eip712SigningDelegate;

  /**
   * Creates a new Eip712AccountContract.
   *
   * @param publicKeyX - The x coordinate of the secp256k1 public key (32 bytes)
   * @param publicKeyY - The y coordinate of the secp256k1 public key (32 bytes)
   * @param authWitnessProvider - Provider that handles auth witness creation
   * @param signingDelegate - Optional delegate that creates EIP-712 capsules for signing
   */
  constructor(
    publicKeyX: Buffer,
    publicKeyY: Buffer,
    authWitnessProvider: AuthWitnessProvider,
    signingDelegate?: Eip712SigningDelegate,
  ) {
    if (publicKeyX.length !== 32 || publicKeyY.length !== 32) {
      throw new Error("Public key coordinates must be 32 bytes each");
    }
    this.publicKeyX = publicKeyX;
    this.publicKeyY = publicKeyY;
    this.authWitnessProvider = authWitnessProvider;
    this.signingDelegate = signingDelegate;
  }

  /**
   * Returns the contract artifact for deployment.
   */
  getContractArtifact(): Promise<ContractArtifact> {
    return Promise.resolve(Eip712AccountContractArtifact);
  }

  /**
   * Returns the initialization function and its arguments.
   * The constructor takes the public key coordinates as u8 arrays.
   */
  async getInitializationFunctionAndArgs(): Promise<{
    constructorName: string;
    constructorArgs: unknown[];
  }> {
    return {
      constructorName: "constructor",
      constructorArgs: [
        Array.from(this.publicKeyX), // Convert Buffer to number array for Noir
        Array.from(this.publicKeyY),
      ],
    };
  }

  /**
   * Returns an Account instance for creating tx requests and authorizing actions.
   * Uses Eip712AccountEntrypoint for EIP-712 capsule-based signing.
   */
  getAccount(address: CompleteAddress): Account {
    const authWitnessProvider = this.getAuthWitnessProvider(address);
    return new BaseAccount(
      new Eip712AccountEntrypoint(address.address, authWitnessProvider, this.signingDelegate),
      authWitnessProvider,
      address,
    );
  }

  /**
   * Returns the auth witness provider.
   * This delegates to EIP-712 signing.
   */
  getAuthWitnessProvider(_address: CompleteAddress): AuthWitnessProvider {
    return this.authWitnessProvider;
  }
}
