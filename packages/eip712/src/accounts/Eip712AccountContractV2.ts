/**
 * EIP-712 V2 Account Contract Implementation
 *
 * V2 version with variable argument types per function call.
 * Each argument can be bytes32, uint256, or address, enabling human-readable
 * display in MetaMask. Type validity is constrained via Merkle tree whitelist.
 */

import type { ContractArtifact } from "@aztec/aztec.js/abi";
import {
  type AccountContract,
  type Account,
  BaseAccount,
  type AuthWitnessProvider,
} from "@aztec/aztec.js/account";
import type { CompleteAddress } from "@aztec/aztec.js/addresses";
import { Eip712AccountEntrypointV2 } from "./Eip712AccountEntrypointV2.js";
import type { Eip712SigningDelegateV2 } from "./Eip712AuthWitnessProviderV2.js";
import { Eip712AccountV2ContractArtifact } from "../artifacts.js";

export class Eip712AccountContractV2 implements AccountContract {
  private readonly publicKeyX: Buffer;
  private readonly publicKeyY: Buffer;
  private readonly authWitnessProvider: AuthWitnessProvider;
  private readonly signingDelegate?: Eip712SigningDelegateV2;

  constructor(
    publicKeyX: Buffer,
    publicKeyY: Buffer,
    authWitnessProvider: AuthWitnessProvider,
    signingDelegate?: Eip712SigningDelegateV2,
  ) {
    if (publicKeyX.length !== 32 || publicKeyY.length !== 32) {
      throw new Error("Public key coordinates must be 32 bytes each");
    }
    this.publicKeyX = publicKeyX;
    this.publicKeyY = publicKeyY;
    this.authWitnessProvider = authWitnessProvider;
    this.signingDelegate = signingDelegate;
  }

  getContractArtifact(): Promise<ContractArtifact> {
    return Promise.resolve(Eip712AccountV2ContractArtifact);
  }

  async getInitializationFunctionAndArgs(): Promise<{
    constructorName: string;
    constructorArgs: unknown[];
  }> {
    return {
      constructorName: "constructor",
      constructorArgs: [
        Array.from(this.publicKeyX),
        Array.from(this.publicKeyY),
      ],
    };
  }

  getAccount(address: CompleteAddress): Account {
    const authWitnessProvider = this.getAuthWitnessProvider(address);
    return new BaseAccount(
      new Eip712AccountEntrypointV2(address.address, authWitnessProvider, this.signingDelegate),
      authWitnessProvider,
      address,
    );
  }

  getAuthWitnessProvider(_address: CompleteAddress): AuthWitnessProvider {
    return this.authWitnessProvider;
  }
}
