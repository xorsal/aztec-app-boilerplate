/**
 * MetaMask EIP-712 V2 Signing Delegate
 *
 * Bridges MetaMask's signTypedData with the V2 EIP-712 capsule system.
 * V2 adds per-argument type annotations (bytes32/uint256/address) and
 * Merkle proofs for the variable argument type whitelist.
 *
 * Per-slot design: Each call slot has its own FunctionCall{N} and Arguments{N} type.
 * No padding — call count determines which entrypoint_N to use.
 *
 * When the entrypoint calls createWitnessCapsuleV2(), this delegate:
 * 1. Converts FunctionCall[] to FunctionCallInputV2[] (with argTypes inferred from artifact)
 * 2. Builds EIP-712 typed data with per-slot FunctionCall{N}/Arguments{N} types
 * 3. Calls walletClient.signTypedData() - MetaMask shows readable function names
 * 4. Gets per-call Merkle proofs from respective FunctionCall{N} trees
 * 5. Serializes to capsule (15 + 64*N Fields)
 */

import type { ContractArtifact } from "@aztec/aztec.js/abi";
import type { AuthWitnessProvider } from "@aztec/aztec.js/account";
import type { AztecAddress } from "@aztec/aztec.js/addresses";
import { Fr } from "@aztec/aztec.js/fields";
import type { FunctionCall } from "@aztec/stdlib/abi";
import { FunctionType } from "@aztec/stdlib/abi";
import { AuthWitness } from "@aztec/stdlib/auth-witness";
import { Capsule } from "@aztec/stdlib/tx";
import { hexToBytes, pad, toHex, type Hex, type WalletClient } from "viem";

import type { Eip712SigningDelegateV2 } from "@aztec-app/eip712";
import {
  Eip712EncoderV2,
  DEFAULT_ACCOUNT_DATA,
  type FunctionCallInputV2,
  type FunctionCallV2,
  type ArgumentType,
  MAX_ENTRYPOINT_CALLS,
  MAX_SIGNATURE_SIZE_V2,
  MAX_SERIALIZED_ARGS_V2,
  MAX_ARGS_TYPE_STRING_LEN,
  MERKLE_DEPTH,
  EIP712_WITNESS_V2_SLOTS,
  DEFAULT_VERIFYING_CONTRACT_V2,
  buildArgumentsTypeString,
  buildFunctionSignature,
  findFunctionArtifact,
  getMerkleProof,
  computeFcTypeHashBytes,
  computeArgsTypeHashBytes,
} from "@aztec-app/eip712";

/**
 * Infer per-argument EIP-712 types from a function artifact's parameters.
 * Noir types are flattened (structs expand to multiple fields) to match
 * the flat Fr[] args from the SDK's FunctionCall.
 */
function inferArgTypes(
  artifact: ContractArtifact,
  callName: string,
  argCount: number,
): ArgumentType[] {
  const func = findFunctionArtifact(artifact, callName);
  if (!func) {
    return Array(argCount).fill("bytes32") as ArgumentType[];
  }

  const types: ArgumentType[] = [];

  function flattenType(abiType: any): void {
    if (typeof abiType === "string") {
      types.push("bytes32");
      return;
    }

    switch (abiType.kind) {
      case "field":
        types.push("bytes32");
        break;
      case "integer":
        types.push("uint256");
        break;
      case "boolean":
        types.push("uint256");
        break;
      case "struct":
        if (abiType.fields && abiType.fields.length > 0) {
          for (const field of abiType.fields) {
            flattenType(field.type);
          }
        } else {
          types.push("bytes32");
        }
        break;
      case "array":
        for (let i = 0; i < (abiType.length ?? 1); i++) {
          flattenType(abiType.type);
        }
        break;
      default:
        types.push("bytes32");
    }
  }

  for (const param of func.parameters) {
    flattenType(param.type);
  }

  // Match the actual arg count (SDK may have padded/trimmed)
  if (types.length > argCount) {
    return types.slice(0, argCount);
  }
  while (types.length < argCount) {
    types.push("bytes32");
  }
  return types;
}

/**
 * MetaMask signing delegate for EIP-712 V2 typed data signing.
 *
 * Implements both Eip712SigningDelegateV2 (capsule creation) and
 * AuthWitnessProvider (returns empty witnesses since signatures
 * are delivered via capsules).
 */
export class MetaMaskEip712SigningDelegateV2
  implements Eip712SigningDelegateV2, AuthWitnessProvider
{
  private readonly artifactMap = new Map<string, ContractArtifact>();
  private readonly encoder: Eip712EncoderV2;

  constructor(
    private readonly walletClient: WalletClient,
    private readonly account: Hex,
    private readonly chainId: bigint = 31337n,
  ) {
    this.encoder = new Eip712EncoderV2({ chainId });
  }

  /**
   * Register a contract artifact for function signature and type resolution.
   */
  registerContractArtifact(
    address: AztecAddress,
    artifact: ContractArtifact,
  ): void {
    this.artifactMap.set(address.toString(), artifact);
  }

  /**
   * Creates a V2 EIP-712 witness capsule for the given function calls.
   * Each call has its own FunctionCall{N} and Arguments{N} type.
   * No padding — capsule slot selected by call count.
   */
  async createWitnessCapsuleV2(
    calls: FunctionCall[],
    txNonce: bigint,
    contractAddress: AztecAddress,
  ): Promise<Capsule> {
    const functionCalls = this.convertToFunctionCallInputsV2(calls);
    const callCount = functionCalls.length;

    if (callCount === 0 || callCount > MAX_ENTRYPOINT_CALLS) {
      throw new Error(`Invalid call count: ${callCount} (must be 1-${MAX_ENTRYPOINT_CALLS})`);
    }

    const perCallArgTypes = functionCalls.map(c => c.argTypes);

    // Build FunctionCallV2 objects for EIP-712 typed data (per-call types)
    const fcObjects = functionCalls.map((c) => this.buildFunctionCallV2(c));

    const accountData = {
      address: pad(toHex(contractAddress.toField().toBigInt()), {
        size: 32,
      }) as Hex,
      walletName: DEFAULT_ACCOUNT_DATA.walletName,
      version: DEFAULT_ACCOUNT_DATA.version,
    };

    const txMetadata = {
      feePaymentMethod: 0,
      cancellable: false,
      txNonce,
    };

    // Build typed data with per-slot Arguments{N} types
    const typedData = this.encoder.buildEntrypointTypedData2(
      fcObjects,
      perCallArgTypes,
      accountData,
      txMetadata,
      DEFAULT_VERIFYING_CONTRACT_V2,
    );

    // Sign via MetaMask - user sees human-readable function names and typed arguments
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

    // Get per-call Merkle proofs from respective FunctionCall{N} trees
    const proofs = await Promise.all(
      functionCalls.map((call, i) => getMerkleProof(`FunctionCall${i + 1}`, call.argTypes))
    );

    // Build oracle data with per-call type/proof data and serialize to capsule
    const oracleData = this.buildOracleData(
      functionCalls,
      ecdsaSignature,
      proofs,
      accountData,
      contractAddress.toField().toBigInt(),
    );

    const capsuleData = this.serializeToCapsule(oracleData, callCount);
    return new Capsule(
      contractAddress,
      new Fr(EIP712_WITNESS_V2_SLOTS[callCount]),
      capsuleData,
    );
  }

  /**
   * Returns empty auth witness since signatures are delivered via capsules.
   */
  async createAuthWit(messageHash: Fr): Promise<AuthWitness> {
    return new AuthWitness(messageHash, []);
  }

  // ===========================================================================
  // Private helpers
  // ===========================================================================

  private convertToFunctionCallInputsV2(
    calls: FunctionCall[],
  ): FunctionCallInputV2[] {
    return calls.map((call) => {
      const artifact = this.artifactMap.get(call.to.toString());
      const args = call.args.map((arg) => arg.toBigInt());
      const argTypes = artifact
        ? inferArgTypes(artifact, call.name, args.length)
        : (Array(args.length).fill("bytes32") as ArgumentType[]);

      if (artifact) {
        const func = findFunctionArtifact(artifact, call.name);
        if (func) {
          return {
            targetAddress: call.to.toField().toBigInt(),
            functionSignature: buildFunctionSignature(func),
            args,
            argTypes,
            isPublic: call.type === FunctionType.PUBLIC,
          };
        }
      }

      console.warn(
        `[SigningDelegateV2] No artifact for ${call.name} at ${call.to}`,
      );
      return {
        targetAddress: call.to.toField().toBigInt(),
        functionSignature: `unknown_${call.name}`,
        args,
        argTypes,
        isPublic: call.type === FunctionType.PUBLIC,
      };
    });
  }

  private buildFunctionCallV2(
    call: FunctionCallInputV2,
  ): FunctionCallV2 {
    const contract = pad(toHex(call.targetAddress), {
      size: 32,
    }) as Hex;

    const arguments_: Record<string, bigint> = {};
    for (let i = 0; i < call.argTypes.length; i++) {
      arguments_[`argument${i + 1}`] = call.args[i] ?? 0n;
    }

    return {
      contract,
      functionSignature: call.functionSignature,
      arguments: arguments_,
      isPublic: call.isPublic ?? false,
      hideMsgSender: call.hideMsgSender ?? false,
      isStatic: call.isStatic ?? false,
    };
  }

  // ===========================================================================
  // Oracle data building and capsule serialization
  // ===========================================================================

  private buildOracleData(
    calls: FunctionCallInputV2[],
    ecdsaSignature: Uint8Array,
    merkleProofs: { siblingPath: Fr[]; leafIndex: number }[],
    accountData: { walletName: string; version: string },
    accountAddressBigInt: bigint,
  ) {
    const callCount = calls.length;
    const functionSignatures: Uint8Array[] = [];
    const signatureLengths: number[] = [];
    const functionArgs: bigint[][] = [];
    const argsLengths: number[] = [];
    const targetAddresses: bigint[] = [];
    const isPublicArr: boolean[] = [];
    const hideMsgSenderArr: boolean[] = [];
    const isStaticArr: boolean[] = [];
    const argsTypeStrings: Uint8Array[] = [];
    const argsTypeStringLengths: number[] = [];
    const merkleProofArrays: Fr[][] = [];
    const merkleLeafIndices: number[] = [];
    const fcTypeHashes: Uint8Array[] = [];
    const argsTypeHashesArr: Uint8Array[] = [];

    for (let i = 0; i < callCount; i++) {
      const call = calls[i];
      const slotNum = i + 1;

      // Function signature
      const sigBytes = new TextEncoder().encode(call.functionSignature);
      const funcSig = new Uint8Array(MAX_SIGNATURE_SIZE_V2);
      funcSig.set(sigBytes.slice(0, MAX_SIGNATURE_SIZE_V2));
      functionSignatures.push(funcSig);
      signatureLengths.push(Math.min(sigBytes.length, MAX_SIGNATURE_SIZE_V2));

      // Function args (padded to MAX_SERIALIZED_ARGS_V2)
      const args = [...call.args];
      while (args.length < MAX_SERIALIZED_ARGS_V2) {
        args.push(0n);
      }
      functionArgs.push(args.slice(0, MAX_SERIALIZED_ARGS_V2));
      argsLengths.push(Math.min(call.args.length, MAX_SERIALIZED_ARGS_V2));

      targetAddresses.push(call.targetAddress);
      isPublicArr.push(call.isPublic ?? false);
      hideMsgSenderArr.push(call.hideMsgSender ?? false);
      isStaticArr.push(call.isStatic ?? false);

      // Per-call type string (Arguments{N})
      const typeString = buildArgumentsTypeString(`Arguments${slotNum}`, call.argTypes);
      const tsBytes = new TextEncoder().encode(typeString);
      const argsTS = new Uint8Array(MAX_ARGS_TYPE_STRING_LEN);
      argsTS.set(tsBytes.slice(0, MAX_ARGS_TYPE_STRING_LEN));
      argsTypeStrings.push(argsTS);
      argsTypeStringLengths.push(Math.min(tsBytes.length, MAX_ARGS_TYPE_STRING_LEN));

      // Per-call Merkle proof
      merkleProofArrays.push(merkleProofs[i].siblingPath);
      merkleLeafIndices.push(merkleProofs[i].leafIndex);

      // Per-call type hashes
      fcTypeHashes.push(hexToBytes(computeFcTypeHashBytes(`FunctionCall${slotNum}`, call.argTypes)));
      argsTypeHashesArr.push(hexToBytes(computeArgsTypeHashBytes(slotNum, call.argTypes)));
    }

    // Wallet name
    const walletNameBytes = new TextEncoder().encode(accountData.walletName);
    const walletName = new Uint8Array(MAX_SIGNATURE_SIZE_V2);
    walletName.set(walletNameBytes.slice(0, MAX_SIGNATURE_SIZE_V2));

    // Wallet version
    const walletVersionBytes = new TextEncoder().encode(accountData.version);
    const walletVersion = new Uint8Array(32);
    walletVersion.set(walletVersionBytes.slice(0, 32));

    return {
      ecdsaSignature,
      functionSignatures,
      signatureLengths,
      functionArgs,
      argsLengths,
      targetAddresses,
      isPublic: isPublicArr,
      hideMsgSender: hideMsgSenderArr,
      isStatic: isStaticArr,
      argsTypeStrings,
      argsTypeStringLengths,
      merkleProofs: merkleProofArrays,
      merkleLeafIndices,
      fcTypeHashes,
      argsTypeHashes: argsTypeHashesArr,
      walletName,
      walletNameLength: Math.min(
        walletNameBytes.length,
        MAX_SIGNATURE_SIZE_V2,
      ),
      walletVersion,
      walletVersionLength: Math.min(walletVersionBytes.length, 32),
      accountAddress: accountAddressBigInt,
      chainId: this.chainId,
    };
  }

  /**
   * Serialize V2 witness to capsule fields.
   *
   * Layout: 3 + N*32 (call data) + N*32 (type/proof per call) + 12 (metadata)
   * Total: 15 + 64*N fields
   * N=1: 79, N=2: 143, N=3: 207, N=4: 271
   */
  private serializeToCapsule(
    data: ReturnType<typeof MetaMaskEip712SigningDelegateV2.prototype.buildOracleData>,
    callCount: number,
  ): Fr[] {
    const fields: Fr[] = [];

    // [0-2]: Signature (64 bytes -> 3 fields: 31+31+2)
    fields.push(...this.packBytes(data.ecdsaSignature, [31, 31, 2]));

    // N calls, each 32 fields
    for (let callIdx = 0; callIdx < callCount; callIdx++) {
      // Function signature (128 bytes -> 5 fields: 4×31 + 1×4)
      fields.push(
        ...this.packBytes(data.functionSignatures[callIdx], [
          31, 31, 31, 31, 4,
        ]),
      );

      // Signature length
      fields.push(new Fr(data.signatureLengths[callIdx]));

      // Function args (20 fields)
      for (let i = 0; i < MAX_SERIALIZED_ARGS_V2; i++) {
        fields.push(new Fr(data.functionArgs[callIdx][i]));
      }

      // Args length
      fields.push(new Fr(data.argsLengths[callIdx]));

      // Target address
      fields.push(new Fr(data.targetAddresses[callIdx]));

      // is_public, hide_msg_sender, is_static
      fields.push(new Fr(data.isPublic[callIdx] ? 1 : 0));
      fields.push(new Fr(data.hideMsgSender[callIdx] ? 1 : 0));
      fields.push(new Fr(data.isStatic[callIdx] ? 1 : 0));

      // Padding to reach 32 fields per call
      fields.push(Fr.ZERO);
    }

    // N type/proof blocks, each 32 fields
    for (let callIdx = 0; callIdx < callCount; callIdx++) {
      // Args type string (256 bytes -> 9 fields: 8×31 + 1×8)
      fields.push(
        ...this.packBytes(data.argsTypeStrings[callIdx], [
          31, 31, 31, 31, 31, 31, 31, 31, 8,
        ]),
      );

      // Args type string length
      fields.push(new Fr(data.argsTypeStringLengths[callIdx]));

      // Merkle proof (MERKLE_DEPTH fields + padding to 17)
      for (let i = 0; i < MERKLE_DEPTH; i++) {
        fields.push(data.merkleProofs[callIdx][i]);
      }
      for (let i = MERKLE_DEPTH; i < 17; i++) {
        fields.push(Fr.ZERO);
      }

      // Merkle leaf index
      fields.push(new Fr(data.merkleLeafIndices[callIdx]));

      // FunctionCall type hash (32 bytes -> 2 fields: 31+1)
      fields.push(...this.packBytes(data.fcTypeHashes[callIdx], [31, 1]));

      // Arguments type hash (32 bytes -> 2 fields: 31+1)
      fields.push(...this.packBytes(data.argsTypeHashes[callIdx], [31, 1]));
    }

    // Metadata (12 fields)
    // wallet_name (128 bytes -> 5 fields)
    fields.push(...this.packBytes(data.walletName, [31, 31, 31, 31, 4]));

    // wallet_name_length
    fields.push(new Fr(data.walletNameLength));

    // wallet_version (32 bytes -> 2 fields: 31+1)
    fields.push(...this.packBytes(data.walletVersion, [31, 1]));

    // wallet_version_length
    fields.push(new Fr(data.walletVersionLength));

    // account_address
    fields.push(new Fr(data.accountAddress));

    // chain_id
    fields.push(new Fr(data.chainId));

    // padding
    fields.push(Fr.ZERO);

    return fields;
  }

  private packBytes(bytes: Uint8Array, bytesPerField: number[]): Fr[] {
    const fields: Fr[] = [];
    let offset = 0;

    for (const size of bytesPerField) {
      const chunk = bytes.slice(offset, offset + size);
      let value = 0n;
      for (let i = 0; i < chunk.length; i++) {
        value = (value << 8n) | BigInt(chunk[i]);
      }
      fields.push(new Fr(value));
      offset += size;
    }

    return fields;
  }
}
