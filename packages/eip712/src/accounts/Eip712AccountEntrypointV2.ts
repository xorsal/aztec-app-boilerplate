/**
 * EIP-712 V2 Account Entrypoint
 *
 * V2 entrypoint with per-call-count entrypoints (entrypoint_1 through entrypoint_4).
 * Each call slot has its own FunctionCall{N} and Arguments{N} types.
 * The signing delegate creates capsules with per-call Merkle proofs.
 */

import type { AuthWitnessProvider } from "@aztec/aztec.js/account";
import type { AztecAddress } from "@aztec/aztec.js/addresses";
import { Fr } from "@aztec/aztec.js/fields";
import type { EntrypointInterface, ChainInfo } from "@aztec/entrypoints/interfaces";
import type { AccountFeePaymentMethodOptions } from "@aztec/entrypoints/account";
import {
  FunctionCall,
  FunctionSelector,
  FunctionType,
  encodeArguments,
} from "@aztec/stdlib/abi";
import type { GasSettings } from "@aztec/stdlib/gas";
import {
  ExecutionPayload,
  HashedValues,
  TxContext,
  TxExecutionRequest,
} from "@aztec/stdlib/tx";
import { Eip712AccountV2ContractArtifact } from "../artifacts.js";
import type { Eip712SigningDelegateV2 } from "./Eip712AuthWitnessProviderV2.js";
import { MAX_ENTRYPOINT_CALLS } from "../lib/eip712-types-v2.js";

const DEFAULT_CHAIN_ID = 31337;
const DEFAULT_VERSION = 1;

export interface Eip712AccountEntrypointV2Options {
  cancellable?: boolean;
  txNonce?: Fr;
  feePaymentMethodOptions: AccountFeePaymentMethodOptions;
}

interface EncodedFunctionCall {
  args_hash: bigint;
  function_selector: { value: number };
  target_address: { inner: bigint };
  is_public: boolean;
  hide_msg_sender: boolean;
  is_static: boolean;
}

class EncodedAppEntrypointCallsV2 {
  private constructor(
    public readonly hashedArguments: HashedValues[],
    private readonly encodedFunctionCalls: EncodedFunctionCall[],
    public readonly tx_nonce: bigint,
  ) {}

  get function_calls(): EncodedFunctionCall[] {
    return this.encodedFunctionCalls;
  }

  static async create(
    calls: {
      to: AztecAddress;
      selector: FunctionSelector;
      args: Fr[];
      isStatic: boolean;
      type?: string;
    }[],
    txNonce?: Fr,
  ) {
    const nonce = txNonce ?? Fr.random();
    const hashedArguments: HashedValues[] = [];
    const encodedFunctionCalls: EncodedFunctionCall[] = [];

    for (const call of calls) {
      const isPublic = call.type === FunctionType.PUBLIC;

      const argsHashedValues = isPublic
        ? await HashedValues.fromCalldata([
            call.selector.toField(),
            ...call.args,
          ])
        : await HashedValues.fromArgs(call.args);

      hashedArguments.push(argsHashedValues);

      encodedFunctionCalls.push({
        args_hash: argsHashedValues.hash.toBigInt(),
        function_selector: {
          value: Number(call.selector.toField().toBigInt()),
        },
        target_address: { inner: call.to.toField().toBigInt() },
        is_public: isPublic,
        hide_msg_sender: false,
        is_static: call.isStatic,
      });
    }

    // No padding — call count determines which entrypoint_N to use

    return new EncodedAppEntrypointCallsV2(
      hashedArguments,
      encodedFunctionCalls,
      nonce.toBigInt(),
    );
  }

  private functionCallsToFields(): Fr[] {
    return this.encodedFunctionCalls.flatMap((call) => [
      new Fr(call.args_hash),
      new Fr(call.function_selector.value),
      new Fr(call.target_address.inner),
      new Fr(call.is_public ? 1 : 0),
      new Fr(call.hide_msg_sender ? 1 : 0),
      new Fr(call.is_static ? 1 : 0),
    ]);
  }

  toFields(): Fr[] {
    return [...this.functionCallsToFields(), new Fr(this.tx_nonce)];
  }

  async hash(): Promise<Fr> {
    const { poseidon2HashWithSeparator } = await import(
      "@aztec/foundation/crypto/poseidon"
    );
    const { DomainSeparator } = await import("@aztec/constants");

    return poseidon2HashWithSeparator(
      this.toFields(),
      DomainSeparator.SIGNATURE_PAYLOAD,
    );
  }
}

export class Eip712AccountEntrypointV2 implements EntrypointInterface {
  constructor(
    private address: AztecAddress,
    private auth: AuthWitnessProvider,
    private signingDelegate?: Eip712SigningDelegateV2,
    private chainId: number = DEFAULT_CHAIN_ID,
    private version: number = DEFAULT_VERSION,
  ) {}

  async createTxExecutionRequest(
    exec: ExecutionPayload,
    gasSettings: GasSettings,
    chainInfo: ChainInfo,
    options: Eip712AccountEntrypointV2Options,
  ): Promise<TxExecutionRequest> {
    const { authWitnesses, capsules, extraHashedArgs } = exec;
    const callData = await this.#buildEntrypointPayload(exec, options);
    const entrypointHashedArgs = await HashedValues.fromArgs(callData.encodedArgs);

    const txRequest = TxExecutionRequest.from({
      firstCallArgsHash: entrypointHashedArgs.hash,
      origin: this.address,
      functionSelector: callData.functionSelector,
      txContext: new TxContext(chainInfo.chainId.toNumber(), chainInfo.version.toNumber(), gasSettings),
      argsOfCalls: [
        ...callData.encodedCalls.hashedArguments,
        entrypointHashedArgs,
        ...extraHashedArgs,
      ],
      authWitnesses: [...authWitnesses, callData.payloadAuthWitness],
      capsules: [...capsules, ...callData.capsules],
      salt: Fr.random(),
    });

    return txRequest;
  }

  async wrapExecutionPayload(
    exec: ExecutionPayload,
    options?: Eip712AccountEntrypointV2Options,
  ): Promise<ExecutionPayload> {
    if (!this.signingDelegate) {
      return exec;
    }

    const { authWitnesses, capsules, extraHashedArgs, feePayer } = exec;
    const callData = await this.#buildEntrypointPayload(exec, options);

    const entrypointCall = new FunctionCall(
      callData.abi.name,
      this.address,
      callData.functionSelector,
      callData.abi.functionType,
      false,
      callData.abi.isStatic,
      callData.encodedArgs,
      callData.abi.returnTypes,
    );

    return new ExecutionPayload(
      [entrypointCall],
      [callData.payloadAuthWitness, ...authWitnesses],
      [...capsules, ...callData.capsules],
      [...callData.encodedCalls.hashedArguments, ...extraHashedArgs],
      feePayer ?? this.address,
    );
  }

  async #buildEntrypointPayload(exec: ExecutionPayload, options?: Eip712AccountEntrypointV2Options) {
    const { calls } = exec;
    const cancellable = options?.cancellable;
    const txNonce = options?.txNonce;
    const feePaymentMethodOptions = options?.feePaymentMethodOptions ?? 0;

    if (calls.length === 0 || calls.length > MAX_ENTRYPOINT_CALLS) {
      throw new Error(`Invalid call count: ${calls.length} (must be 1-${MAX_ENTRYPOINT_CALLS})`);
    }

    const encodedCalls = await EncodedAppEntrypointCallsV2.create(
      calls.map((call) => ({
        to: call.to,
        selector: call.selector,
        args: call.args,
        isStatic: call.isStatic ?? false,
        type: call.type,
      })),
      txNonce,
    );

    const entrypointName = `entrypoint_${calls.length}`;
    const abi = this.getEntrypointAbi(entrypointName);
    const encodedArgs = encodeArguments(abi, [
      encodedCalls,
      feePaymentMethodOptions,
      !!cancellable,
    ]);

    const functionSelector = await FunctionSelector.fromNameAndParameters(
      abi.name,
      abi.parameters,
    );

    const payloadAuthWitness = await this.auth.createAuthWit(
      await encodedCalls.hash(),
    );

    const capsules = [];
    if (this.signingDelegate) {
      const capsule = await this.signingDelegate.createWitnessCapsuleV2(
        calls,
        encodedCalls.tx_nonce,
        this.address,
      );
      capsules.push(capsule);
    }

    return {
      encodedCalls,
      abi,
      encodedArgs,
      functionSelector,
      payloadAuthWitness,
      capsules,
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private getEntrypointAbi(name: string): any {
    const abi = Eip712AccountV2ContractArtifact.functions.find(
      (f) => f.name === name,
    );
    if (!abi) {
      throw new Error(
        `Function '${name}' not found in Eip712AccountV2 artifact`,
      );
    }
    return abi;
  }
}
