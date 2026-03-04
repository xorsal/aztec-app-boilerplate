/**
 * EIP-712 Account Entrypoint
 *
 * Entrypoint implementation that uses the EIP-712 capsule-based entrypoint
 * for human-readable transaction signing via MetaMask.
 *
 * The signing delegate creates EIP-712 capsules during payload construction,
 * eliminating the former PendingTxContext side-channel.
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
import { Eip712AccountContractArtifact } from "../artifacts.js";
import type { Eip712SigningDelegate } from "./Eip712AuthWitnessProvider.js";

// Constants from @aztec/entrypoints
const DEFAULT_CHAIN_ID = 31337;
const DEFAULT_VERSION = 1;

/**
 * Options for EIP-712 account entrypoint
 */
export interface Eip712AccountEntrypointOptions {
  /** Whether the transaction can be cancelled */
  cancellable?: boolean;
  /** A nonce to inject into the app payload of the transaction */
  txNonce?: Fr;
  /** Options that configure how the account contract behaves depending on the fee payment method */
  feePaymentMethodOptions: AccountFeePaymentMethodOptions;
}

/**
 * Encoded function call for an Aztec entrypoint.
 *
 * IMPORTANT: encodeArguments expects PRIMITIVE values, not Fr objects.
 * The encoder will create Fr internally from the primitives.
 *
 * - args_hash: bigint (Field value)
 * - function_selector.value: number (u32) - NOTE: SDK encoder uses .value not .inner
 * - target_address.inner: bigint (Field value)
 */
interface EncodedFunctionCall {
  args_hash: bigint; // Field as bigint
  function_selector: { value: number }; // u32 as number - encoder uses .value
  target_address: { inner: bigint }; // Field as bigint
  is_public: boolean;
  hide_msg_sender: boolean;
  is_static: boolean;
}

/**
 * EncodedAppEntrypointCalls - simplified version matching SDK's encoding
 *
 * IMPORTANT: All field values passed to encodeArguments must be primitives (bigint),
 * not Fr objects. The encoder handles conversion internally.
 */
class EncodedAppEntrypointCalls {
  private constructor(
    public readonly hashedArguments: HashedValues[],
    private readonly encodedFunctionCalls: EncodedFunctionCall[],
    public readonly tx_nonce: bigint, // bigint for encodeArguments
  ) {}

  // Snake_case getter for Noir compatibility
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

    // Process actual calls
    for (const call of calls) {
      const isPublic = call.type === FunctionType.PUBLIC;

      // For public functions, use fromCalldata (includes selector, PUBLIC_CALLDATA separator)
      // For private functions, use fromArgs (just args, FUNCTION_ARGS separator)
      //
      // Note: Both private and public functions use EIP-712 signing.
      // For public functions, selector is prepended to args in the AppPayload's args_hash.
      const argsHashedValues = isPublic
        ? await HashedValues.fromCalldata([
            call.selector.toField(),
            ...call.args,
          ])
        : await HashedValues.fromArgs(call.args);

      hashedArguments.push(argsHashedValues);

      // All field values must be bigint for encodeArguments
      // NOTE: function_selector uses .value (not .inner) to match SDK's Selector class
      encodedFunctionCalls.push({
        args_hash: argsHashedValues.hash.toBigInt(),
        function_selector: {
          value: Number(call.selector.toField().toBigInt()),
        }, // u32 - .value for SDK encoder
        target_address: { inner: call.to.toField().toBigInt() }, // bigint
        is_public: isPublic,
        hide_msg_sender: false,
        is_static: call.isStatic,
      });
    }

    // Pad to 5 calls
    while (encodedFunctionCalls.length < 5) {
      const emptyHash = await HashedValues.fromArgs([]);
      hashedArguments.push(emptyHash);
      encodedFunctionCalls.push({
        args_hash: 0n, // bigint zero
        function_selector: { value: 0 }, // u32 zero - .value for SDK encoder
        target_address: { inner: 0n }, // bigint zero
        is_public: false,
        hide_msg_sender: false,
        is_static: false,
      });
    }

    return new EncodedAppEntrypointCalls(
      hashedArguments,
      encodedFunctionCalls,
      nonce.toBigInt(),
    );
  }

  /**
   * Serializes the function calls to an array of fields for hashing
   */
  private functionCallsToFields(): Fr[] {
    return this.encodedFunctionCalls.flatMap((call) => [
      new Fr(call.args_hash), // Convert bigint to Fr
      new Fr(call.function_selector.value), // Convert u32 to Fr - .value to match SDK
      new Fr(call.target_address.inner), // Convert bigint to Fr
      new Fr(call.is_public ? 1 : 0),
      new Fr(call.hide_msg_sender ? 1 : 0),
      new Fr(call.is_static ? 1 : 0),
    ]);
  }

  /**
   * Serializes the payload to an array of fields for hashing
   */
  toFields(): Fr[] {
    return [...this.functionCallsToFields(), new Fr(this.tx_nonce)];
  }

  async hash(): Promise<Fr> {
    // Import poseidon2HashWithSeparator to match SDK's hashing
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

/**
 * EIP-712 capsule-based entrypoint for human-readable transaction signing.
 *
 * The signing delegate creates capsules on demand during payload construction.
 * When no delegate is provided (e.g. account deployment via MultiCallEntrypoint),
 * the entrypoint operates without capsules.
 */
export class Eip712AccountEntrypoint implements EntrypointInterface {
  constructor(
    private address: AztecAddress,
    private auth: AuthWitnessProvider,
    private signingDelegate?: Eip712SigningDelegate,
    private chainId: number = DEFAULT_CHAIN_ID,
    private version: number = DEFAULT_VERSION,
  ) {}

  async createTxExecutionRequest(
    exec: ExecutionPayload,
    gasSettings: GasSettings,
    chainInfo: ChainInfo,
    options: Eip712AccountEntrypointOptions,
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
    options?: Eip712AccountEntrypointOptions,
  ): Promise<ExecutionPayload> {
    // Without a signing delegate (e.g. during account deployment via
    // MultiCallEntrypoint), return the payload unwrapped to avoid a
    // Noir assertion failure from missing capsule data.
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

  /**
   * Builds the shared data needed for both creating a tx execution request
   * and wrapping an execution payload. This includes encoding calls, creating
   * the EIP-712 capsule via the signing delegate, and building the auth witness.
   */
  async #buildEntrypointPayload(exec: ExecutionPayload, options?: Eip712AccountEntrypointOptions) {
    const { calls } = exec;
    const cancellable = options?.cancellable;
    const txNonce = options?.txNonce;
    const feePaymentMethodOptions = options?.feePaymentMethodOptions ?? 0;

    // Encode the calls for the app payload
    const encodedCalls = await EncodedAppEntrypointCalls.create(
      calls.map((call) => ({
        to: call.to,
        selector: call.selector,
        args: call.args,
        isStatic: call.isStatic ?? false,
        type: call.type, // CRITICAL: Pass function type for public/private distinction
      })),
      txNonce,
    );

    // Get the entrypoint ABI from the compiled artifact
    const abi = this.getEntrypointAbi("entrypoint");
    const encodedArgs = encodeArguments(abi, [
      encodedCalls,
      feePaymentMethodOptions,
      !!cancellable,
    ]);

    const functionSelector = await FunctionSelector.fromNameAndParameters(
      abi.name,
      abi.parameters,
    );

    // Generate the payload auth witness (empty — signature delivered via capsule)
    const payloadAuthWitness = await this.auth.createAuthWit(
      await encodedCalls.hash(),
    );

    // Create EIP-712 capsule via signing delegate (if available)
    const capsules = [];
    if (this.signingDelegate) {
      const capsule = await this.signingDelegate.createWitnessCapsule(
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

  /**
   * Returns the ABI for the specified entrypoint function from the compiled artifact.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private getEntrypointAbi(name: string): any {
    const abi = Eip712AccountContractArtifact.functions.find(
      (f) => f.name === name,
    );
    if (!abi) {
      throw new Error(
        `Function '${name}' not found in Eip712Account artifact`,
      );
    }
    return abi;
  }
}
