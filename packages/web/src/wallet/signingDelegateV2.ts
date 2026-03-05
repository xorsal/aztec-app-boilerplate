/**
 * MetaMask EIP-712 V2 Signing Delegate
 *
 * Bridges MetaMask's signTypedData with the V2 EIP-712 capsule system.
 * V2 adds per-argument type annotations (bytes32/uint256/int256) and
 * Merkle proofs for the variable argument type whitelist.
 *
 * When the entrypoint calls createWitnessCapsuleV2(), this delegate:
 * 1. Converts FunctionCall[] to FunctionCallInputV2[] (with argTypes inferred from artifact)
 * 2. Builds EIP-712 typed data via Eip712EncoderV2
 * 3. Calls walletClient.signTypedData() - MetaMask shows readable function names
 * 4. Gets Merkle proofs for each call's argument types
 * 5. Serializes to capsule (143 Fields)
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
  type MerkleProof,
  ACCOUNT_MAX_CALLS_V2,
  MAX_SIGNATURE_SIZE_V2,
  MAX_SERIALIZED_ARGS_V2,
  MAX_ARGS_TYPE_STRING_LEN,
  MERKLE_DEPTH,
  EIP712_WITNESS_V2_2_SLOT,
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
        types.push(abiType.sign === "signed" ? "int256" : "uint256");
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
   * Includes per-argument type annotations and Merkle proofs.
   */
  async createWitnessCapsuleV2(
    calls: FunctionCall[],
    txNonce: bigint,
    contractAddress: AztecAddress,
  ): Promise<Capsule> {
    const functionCalls = this.convertToFunctionCallInputsV2(calls);

    // Pad to 2 calls
    const paddedCalls = [...functionCalls];
    while (paddedCalls.length < ACCOUNT_MAX_CALLS_V2) {
      paddedCalls.push({
        targetAddress: 0n,
        functionSignature: "",
        args: [],
        argTypes: [],
        isPublic: false,
        hideMsgSender: false,
        isStatic: false,
      });
    }

    // Build FunctionCallV2 objects for EIP-712 typed data
    const fc1 = this.buildFunctionCallV2(paddedCalls[0]);
    const fc2 = this.buildFunctionCallV2(paddedCalls[1]);

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

    // Build typed data with dynamic Arguments types
    const typedData = this.encoder.buildEntrypointTypedData2(
      fc1,
      fc2,
      paddedCalls[0].argTypes,
      paddedCalls[1].argTypes,
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

    // Get Merkle proofs for each call's argument types
    const proof1 = await getMerkleProof("Arguments1", paddedCalls[0].argTypes);
    const proof2 = await getMerkleProof("Arguments2", paddedCalls[1].argTypes);

    // Build oracle data and serialize to capsule
    const oracleData = this.buildOracleData(
      paddedCalls,
      ecdsaSignature,
      [proof1, proof2],
      accountData,
      contractAddress.toField().toBigInt(),
    );

    const capsuleData = this.serializeToCapsule(oracleData);
    return new Capsule(
      contractAddress,
      new Fr(EIP712_WITNESS_V2_2_SLOT),
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

  private buildFunctionCallV2(call: FunctionCallInputV2): FunctionCallV2 {
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
  // (mirrors Eip712AccountV2 private methods)
  // ===========================================================================

  private buildOracleData(
    calls: FunctionCallInputV2[],
    ecdsaSignature: Uint8Array,
    merkleProofs: MerkleProof[],
    accountData: { walletName: string; version: string },
    accountAddressBigInt: bigint,
  ) {
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
    const mProofs: Fr[][] = [];
    const leafIndices: number[] = [];
    const fcTypeHashArrays: Uint8Array[] = [];
    const argsTypeHashArrays: Uint8Array[] = [];

    for (let i = 0; i < ACCOUNT_MAX_CALLS_V2; i++) {
      const call = calls[i];

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

      // Args type string for Merkle verification
      const structName = `Arguments${i + 1}`;
      const typeString = buildArgumentsTypeString(structName, call.argTypes);
      const tsBytes = new TextEncoder().encode(typeString);
      const typeStr = new Uint8Array(MAX_ARGS_TYPE_STRING_LEN);
      typeStr.set(tsBytes.slice(0, MAX_ARGS_TYPE_STRING_LEN));
      argsTypeStrings.push(typeStr);
      argsTypeStringLengths.push(
        Math.min(tsBytes.length, MAX_ARGS_TYPE_STRING_LEN),
      );

      // Merkle proof
      mProofs.push(merkleProofs[i].siblingPath);
      leafIndices.push(merkleProofs[i].leafIndex);

      // Pre-computed type hashes (Approach 2)
      const fcTypeHash = computeFcTypeHashBytes(structName, call.argTypes);
      fcTypeHashArrays.push(hexToBytes(fcTypeHash));
      const argsTypeHash = computeArgsTypeHashBytes(structName, call.argTypes);
      argsTypeHashArrays.push(hexToBytes(argsTypeHash));
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
      merkleProofs: mProofs,
      merkleLeafIndices: leafIndices,
      fcTypeHashes: fcTypeHashArrays,
      argsTypeHashes: argsTypeHashArrays,
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
   * Serialize V2 witness to capsule fields (143 Fields).
   * Approach 2: per-call stride = 64 (was 60), adds fc_type_hash + args_type_hash.
   */
  private serializeToCapsule(
    data: ReturnType<typeof MetaMaskEip712SigningDelegateV2.prototype.buildOracleData>,
  ): Fr[] {
    const fields: Fr[] = [];

    // [0-2]: Signature (64 bytes -> 3 fields: 31+31+2)
    fields.push(...this.packBytes(data.ecdsaSignature, [31, 31, 2]));

    // [3-130]: 2 calls, each 64 fields
    for (let callIdx = 0; callIdx < ACCOUNT_MAX_CALLS_V2; callIdx++) {
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

      // Args type string (256 bytes -> 9 fields: 8×31 + 1×8)
      fields.push(
        ...this.packBytes(data.argsTypeStrings[callIdx], [
          31, 31, 31, 31, 31, 31, 31, 31, 8,
        ]),
      );

      // Args type string length
      fields.push(new Fr(data.argsTypeStringLengths[callIdx]));

      // Merkle proof (17 fields)
      for (let i = 0; i < MERKLE_DEPTH; i++) {
        fields.push(data.merkleProofs[callIdx][i]);
      }

      // Merkle leaf index
      fields.push(new Fr(data.merkleLeafIndices[callIdx]));

      // FunctionCall type hash (32 bytes -> 2 fields: 31+1)
      fields.push(...this.packBytes(data.fcTypeHashes[callIdx], [31, 1]));

      // Arguments type hash (32 bytes -> 2 fields: 31+1)
      fields.push(...this.packBytes(data.argsTypeHashes[callIdx], [31, 1]));

      // Padding to reach 64 fields per call
      fields.push(Fr.ZERO);
    }

    // [131-135]: wallet_name (128 bytes -> 5 fields)
    fields.push(...this.packBytes(data.walletName, [31, 31, 31, 31, 4]));

    // [136]: wallet_name_length
    fields.push(new Fr(data.walletNameLength));

    // [137-138]: wallet_version (32 bytes -> 2 fields: 31+1)
    fields.push(...this.packBytes(data.walletVersion, [31, 1]));

    // [139]: wallet_version_length
    fields.push(new Fr(data.walletVersionLength));

    // [140]: account_address
    fields.push(new Fr(data.accountAddress));

    // [141]: chain_id
    fields.push(new Fr(data.chainId));

    // [142]: padding
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
