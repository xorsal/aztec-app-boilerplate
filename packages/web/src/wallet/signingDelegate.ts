/**
 * MetaMask EIP-712 Signing Delegate
 *
 * Bridges MetaMask's signTypedData with the EIP-712 capsule system.
 * When the entrypoint calls createWitnessCapsule(), this delegate:
 * 1. Converts FunctionCall[] to FunctionCallInput[] using registered artifacts
 * 2. Builds EIP-712 typed data via Eip712Encoder
 * 3. Calls walletClient.signTypedData() - MetaMask shows readable function names
 * 4. Creates capsule with the external signature
 */

import type { ContractArtifact } from "@aztec/aztec.js/abi";
import type { AuthWitnessProvider } from "@aztec/aztec.js/account";
import type { AztecAddress } from "@aztec/aztec.js/addresses";
import { Fr } from "@aztec/aztec.js/fields";
import type { FunctionCall } from "@aztec/stdlib/abi";
import { FunctionType } from "@aztec/stdlib/abi";
import { AuthWitness } from "@aztec/stdlib/auth-witness";
import type { Capsule } from "@aztec/stdlib/tx";
import { hexToBytes, type Hex, type WalletClient } from "viem";

import type { Eip712SigningDelegate } from "@aztec-app/eip712";
import {
  Eip712Account,
  Eip712Encoder,
  buildFunctionSignature,
  findFunctionArtifact,
  type FunctionCallInput,
} from "@aztec-app/eip712";

/**
 * MetaMask signing delegate for EIP-712 typed data signing.
 *
 * Implements both Eip712SigningDelegate (capsule creation) and
 * AuthWitnessProvider (returns empty witnesses since signatures
 * are delivered via capsules).
 */
export class MetaMaskEip712SigningDelegate
  implements Eip712SigningDelegate, AuthWitnessProvider
{
  private readonly artifactMap = new Map<string, ContractArtifact>();
  private readonly encoder: Eip712Encoder;
  private readonly eip712Account: Eip712Account;

  constructor(
    private readonly walletClient: WalletClient,
    private readonly account: Hex,
    private readonly chainId: bigint = 31337n,
  ) {
    this.encoder = new Eip712Encoder({ chainId });
    this.eip712Account = new Eip712Account(undefined, chainId);
  }

  /**
   * Register a contract artifact for function signature resolution.
   */
  registerContractArtifact(
    address: AztecAddress,
    artifact: ContractArtifact,
  ): void {
    this.artifactMap.set(address.toString(), artifact);
  }

  /**
   * Creates an EIP-712 witness capsule for the given function calls.
   */
  async createWitnessCapsule(
    calls: FunctionCall[],
    txNonce: bigint,
    contractAddress: AztecAddress,
  ): Promise<Capsule> {
    const functionCalls = this.convertToFunctionCallInputs(calls);

    const eip712FunctionCalls = functionCalls.map((call) =>
      Eip712Encoder.createFunctionCall(
        call.targetAddress,
        call.functionSignature,
        call.args,
        !call.isPublic,
      ),
    );

    const typedData = this.encoder.buildEntrypointTypedData5(
      eip712FunctionCalls,
      txNonce,
    );

    // Sign via MetaMask - user sees human-readable function names and arguments
    const signature = await this.walletClient.signTypedData({
      account: this.account,
      ...typedData,
    });

    // Extract r,s (64 bytes) - discard v byte
    const sigBytes = hexToBytes(signature);
    if (sigBytes.length < 64) {
      throw new Error(
        `Invalid signature length: ${sigBytes.length}, expected at least 64 bytes`,
      );
    }
    const ecdsaSignature = sigBytes.slice(0, 64);

    return this.eip712Account.createWitnessCapsule5WithExternalSignature(
      functionCalls,
      txNonce,
      ecdsaSignature,
      contractAddress,
    );
  }

  /**
   * Returns empty auth witness since signatures are delivered via capsules.
   */
  async createAuthWit(messageHash: Fr): Promise<AuthWitness> {
    return new AuthWitness(messageHash, []);
  }

  private convertToFunctionCallInputs(
    calls: FunctionCall[],
  ): FunctionCallInput[] {
    return calls.map((call) => {
      const artifact = this.artifactMap.get(call.to.toString());
      if (artifact) {
        const func = findFunctionArtifact(artifact, call.name);
        if (func) {
          return {
            targetAddress: call.to.toField().toBigInt(),
            functionSignature: buildFunctionSignature(func),
            args: call.args.map((arg) => arg.toBigInt()),
            isPublic: call.type === FunctionType.PUBLIC,
          };
        }
      }

      console.warn(
        `[SigningDelegate] No artifact for ${call.name} at ${call.to}`,
      );
      return {
        targetAddress: call.to.toField().toBigInt(),
        functionSignature: `unknown_${call.name}`,
        args: call.args.map((arg) => arg.toBigInt()),
        isPublic: call.type === FunctionType.PUBLIC,
      };
    });
  }
}
