/**
 * EIP-712 V2 Account Class
 *
 * Handles signing and capsule creation for the V2 contract with variable argument types.
 * Each argument can be bytes32, uint256, or address (chosen by the frontend).
 *
 * Per-slot design: Each call slot has its own FunctionCall{N} and Arguments{N} type.
 * No padding — callCount = actual number of calls.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, type Hex, hexToBytes, bytesToHex, pad, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Eip712EncoderV2, DEFAULT_ACCOUNT_DATA, AZTEC_DOMAIN_V2 } from "./eip712-encoder-v2.js";
import {
  type ArgumentType,
  type AccountData,
  type TxMetadata,
  type FunctionCallV2,
  MAX_ENTRYPOINT_CALLS,
  EIP712_WITNESS_V2_SLOTS,
  EIP712_AUTHWIT_V2_SLOT,
  MAX_SERIALIZED_ARGS_V2,
  MAX_SIGNATURE_SIZE_V2,
  MERKLE_DEPTH,
  DEFAULT_VERIFYING_CONTRACT_V2,
  FC_PRIMARIES,
} from "./eip712-types-v2.js";
import { getMerkleProof, computeFcTypeHashBytes, type MerkleProof } from "./merkle-tree-data.js";
import { Capsule } from "@aztec/stdlib/tx";
import { Fr } from "@aztec/aztec.js/fields";
import { AztecAddress } from "@aztec/aztec.js/addresses";

// =============================================================================
// Types
// =============================================================================

export interface FunctionCallInputV2 {
  targetAddress: bigint;
  functionSignature: string;
  args: bigint[];
  /** Per-argument EIP-712 types (bytes32, uint256, address) */
  argTypes: ArgumentType[];
  isPublic?: boolean;
  hideMsgSender?: boolean;
  isStatic?: boolean;
}

/** Oracle data for V2 per-call-count entrypoint (per-slot types) */
export interface Eip712OracleDataV2_2 {
  ecdsaSignature: Uint8Array;
  // Per-call data
  functionSignatures: Uint8Array[];
  signatureLengths: number[];
  functionArgs: bigint[][];
  argsLengths: number[];
  targetAddresses: bigint[];
  isPublic: boolean[];
  hideMsgSender: boolean[];
  isStatic: boolean[];
  // Per-call type/proof data (N entries each)
  merkleProofs: Fr[][];
  merkleLeafIndices: number[];
  fcTypeHashes: Uint8Array[];
  callHashes: Uint8Array[];
  // Precomputed hashes
  entrypointTypeHash: Uint8Array;
  accountDataHash: Uint8Array;
  txMetadataHash: Uint8Array;
}

/** Oracle data for V2 individual authwit */
export interface Eip712AuthwitOracleDataV2 {
  ecdsaSignature: Uint8Array;
  functionSignature: Uint8Array;
  signatureLength: number;
  functionArgs: bigint[];
  argsLength: number;
  targetAddress: bigint;
  isPublic: boolean;
  merkleProof: Fr[];
  merkleLeafIndex: number;
  innerHash: bigint;
  /** Pre-computed FunctionCallAuthorization type hash */
  fcAuthTypeHash: Uint8Array;
  /** Pre-computed authwit message hash (hashStruct of FunctionCallAuthorization) */
  authwitMessageHash: Uint8Array;
}

// =============================================================================
// V2 Account Class
// =============================================================================

export class Eip712AccountV2 {
  private privateKey: Hex;
  private publicKeyX: Uint8Array;
  private publicKeyY: Uint8Array;
  private encoder: Eip712EncoderV2;
  private _chainId: bigint;

  constructor(privateKey?: Hex, chainId: bigint = 31337n) {
    if (privateKey) {
      this.privateKey = privateKey;
    } else {
      const randomBytes = new Uint8Array(32);
      crypto.getRandomValues(randomBytes);
      this.privateKey = bytesToHex(randomBytes);
    }

    const publicKey = secp256k1.getPublicKey(
      hexToBytes(this.privateKey).slice(0, 32),
      false,
    );
    this.publicKeyX = publicKey.slice(1, 33);
    this.publicKeyY = publicKey.slice(33, 65);

    this._chainId = chainId;
    this.encoder = new Eip712EncoderV2({ chainId });
  }

  get chainId(): bigint {
    return this._chainId;
  }

  getPublicKey(): { x: Uint8Array; y: Uint8Array } {
    return { x: this.publicKeyX, y: this.publicKeyY };
  }

  getPublicKeyArrays(): { x: number[]; y: number[] } {
    return {
      x: Array.from(this.publicKeyX),
      y: Array.from(this.publicKeyY),
    };
  }

  getEthAddress(): Hex {
    const pubKeyBytes = new Uint8Array(64);
    pubKeyBytes.set(this.publicKeyX, 0);
    pubKeyBytes.set(this.publicKeyY, 32);
    const hash = keccak256(pubKeyBytes);
    return `0x${hash.slice(-40)}` as Hex;
  }

  // ==========================================================================
  // Per-Call-Count Entrypoint Methods
  // ==========================================================================

  /**
   * Create a Capsule for V2 per-call-count entrypoint.
   * Each call has its own FunctionCall{N} and Arguments{N} type.
   * No padding — capsule slot selected by call count.
   */
  async createWitnessCapsule2(
    calls: FunctionCallInputV2[],
    txNonce: bigint,
    contractAddress: AztecAddress,
    verifyingContract: Hex = DEFAULT_VERIFYING_CONTRACT_V2,
  ): Promise<Capsule> {
    if (calls.length === 0) {
      throw new Error("At least one call is required");
    }
    if (calls.length > MAX_ENTRYPOINT_CALLS) {
      throw new Error(`Too many calls: ${calls.length} > ${MAX_ENTRYPOINT_CALLS}`);
    }

    const perCallArgTypes = calls.map(c => c.argTypes);

    // Build function call objects for EIP-712
    const functionCalls = calls.map(c => this.buildFunctionCallV2(c));

    const accountData: AccountData = {
      address: pad(toHex(contractAddress.toField().toBigInt()), { size: 32 }),
      walletName: DEFAULT_ACCOUNT_DATA.walletName,
      version: DEFAULT_ACCOUNT_DATA.version,
    };

    const txMetadata: TxMetadata = {
      feePaymentMethod: 0,
      cancellable: false,
      txNonce,
    };

    // Build and sign typed data (per-slot Arguments types)
    const typedData = this.encoder.buildEntrypointTypedData2(
      functionCalls,
      perCallArgTypes,
      accountData,
      txMetadata,
      verifyingContract,
    );

    const account = privateKeyToAccount(this.privateKey);
    const signature = await account.signTypedData(typedData);
    const sigBytes = hexToBytes(signature);
    const ecdsaSignature = sigBytes.slice(0, 64);

    // Get per-call Merkle proofs from respective FunctionCall{N} trees
    const proofs = await Promise.all(
      calls.map((call, i) => getMerkleProof(`FunctionCall${i + 1}`, call.argTypes))
    );

    // Build oracle data with per-call type/proof data
    const oracleData = this.buildOracleDataV2_2(
      calls,
      ecdsaSignature,
      proofs,
      accountData,
      txMetadata,
    );

    const callCount = calls.length;
    const capsuleData = this.serializeWitnessV2_2ToCapsule(oracleData, callCount);
    return new Capsule(
      contractAddress,
      new Fr(EIP712_WITNESS_V2_SLOTS[callCount]),
      capsuleData,
    );
  }

  private buildFunctionCallV2(call: FunctionCallInputV2): FunctionCallV2 {
    const contract = pad(toHex(call.targetAddress), { size: 32 }) as Hex;

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

  private buildOracleDataV2_2(
    calls: FunctionCallInputV2[],
    ecdsaSignature: Uint8Array,
    merkleProofs: MerkleProof[],
    accountData: AccountData,
    txMetadata: TxMetadata,
  ): Eip712OracleDataV2_2 {
    const callCount = calls.length;
    const functionSignatures: Uint8Array[] = [];
    const signatureLengths: number[] = [];
    const functionArgs: bigint[][] = [];
    const argsLengths: number[] = [];
    const targetAddresses: bigint[] = [];
    const isPublic: boolean[] = [];
    const hideMsgSender: boolean[] = [];
    const isStatic: boolean[] = [];
    const merkleProofArrays: Fr[][] = [];
    const merkleLeafIndices: number[] = [];
    const fcTypeHashes: Uint8Array[] = [];

    for (let i = 0; i < callCount; i++) {
      const call = calls[i];
      const slotNum = i + 1;

      // Function signature
      const sigBytes = new TextEncoder().encode(call.functionSignature);
      const funcSig = new Uint8Array(MAX_SIGNATURE_SIZE_V2);
      funcSig.set(sigBytes.slice(0, MAX_SIGNATURE_SIZE_V2));
      functionSignatures.push(funcSig);
      signatureLengths.push(Math.min(sigBytes.length, MAX_SIGNATURE_SIZE_V2));

      // Function args
      const args = [...call.args];
      while (args.length < MAX_SERIALIZED_ARGS_V2) {
        args.push(0n);
      }
      functionArgs.push(args.slice(0, MAX_SERIALIZED_ARGS_V2));
      argsLengths.push(Math.min(call.args.length, MAX_SERIALIZED_ARGS_V2));

      targetAddresses.push(call.targetAddress);
      isPublic.push(call.isPublic ?? false);
      hideMsgSender.push(call.hideMsgSender ?? false);
      isStatic.push(call.isStatic ?? false);

      // Per-call Merkle proof
      merkleProofArrays.push(merkleProofs[i].siblingPath);
      merkleLeafIndices.push(merkleProofs[i].leafIndex);

      // Per-call FunctionCall type hash
      fcTypeHashes.push(hexToBytes(computeFcTypeHashBytes(`FunctionCall${slotNum}`, call.argTypes)));
    }

    // Precomputed hashes
    const perCallArgTypes = calls.map(c => c.argTypes);
    const entrypointTypeHash = hexToBytes(Eip712EncoderV2.computeEntrypointTypeHash(perCallArgTypes));
    const accountDataHash = hexToBytes(Eip712EncoderV2.hashAccountData(accountData));
    const txMetadataHash = hexToBytes(Eip712EncoderV2.hashTxMetadata(txMetadata));

    const callHashes: Uint8Array[] = [];
    for (let i = 0; i < callCount; i++) {
      const call = calls[i];
      const slotNum = i + 1;
      const contract = pad(toHex(call.targetAddress), { size: 32 }) as Hex;
      const callHash = Eip712EncoderV2.hashFunctionCallV2(
        FC_PRIMARIES[slotNum],
        `Arguments${slotNum}`,
        contract,
        call.functionSignature,
        call.argTypes,
        call.args,
        call.isPublic ?? false,
        call.hideMsgSender ?? false,
        call.isStatic ?? false,
      );
      callHashes.push(hexToBytes(callHash));
    }

    return {
      ecdsaSignature,
      functionSignatures,
      signatureLengths,
      functionArgs,
      argsLengths,
      targetAddresses,
      isPublic,
      hideMsgSender,
      isStatic,
      merkleProofs: merkleProofArrays,
      merkleLeafIndices,
      fcTypeHashes,
      callHashes,
      entrypointTypeHash,
      accountDataHash,
      txMetadataHash,
    };
  }

  /**
   * Serialize V2 witness to capsule fields.
   *
   * Layout: 3 + N*32 (call data) + N*22 (proof per call) + 6 (footer)
   * Total: 9 + 54*N fields
   * N=1: 63, N=2: 117, N=3: 171, N=4: 225
   */
  private serializeWitnessV2_2ToCapsule(data: Eip712OracleDataV2_2, callCount: number): Fr[] {
    const fields: Fr[] = [];

    // [0-2]: Signature (64 bytes -> 3 fields: 31+31+2)
    fields.push(...this.packBytes(data.ecdsaSignature, [31, 31, 2]));

    // N calls, each 32 fields (UNCHANGED)
    for (let callIdx = 0; callIdx < callCount; callIdx++) {
      // Function signature (128 bytes -> 5 fields: 4×31 + 1×4)
      fields.push(
        ...this.packBytes(data.functionSignatures[callIdx], [31, 31, 31, 31, 4]),
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

    // N proof blocks, each 22 fields
    for (let callIdx = 0; callIdx < callCount; callIdx++) {
      // Merkle proof (MERKLE_DEPTH fields + padding to 17)
      for (let i = 0; i < MERKLE_DEPTH; i++) {
        fields.push(data.merkleProofs[callIdx][i]);
      }
      for (let i = MERKLE_DEPTH; i < 17; i++) {
        fields.push(Fr.ZERO);
      }

      // Merkle leaf index
      fields.push(new Fr(data.merkleLeafIndices[callIdx]));

      // FC type hash (32 bytes -> 2 fields: 31+1)
      fields.push(...this.packBytes(data.fcTypeHashes[callIdx], [31, 1]));

      // Call hash (32 bytes -> 2 fields: 31+1)
      fields.push(...this.packBytes(data.callHashes[callIdx], [31, 1]));
    }

    // Footer (6 fields)
    fields.push(...this.packBytes(data.entrypointTypeHash, [31, 1]));
    fields.push(...this.packBytes(data.accountDataHash, [31, 1]));
    fields.push(...this.packBytes(data.txMetadataHash, [31, 1]));

    return fields;
  }

  // ==========================================================================
  // Authwit Methods (unchanged — single call, unnumbered Arguments)
  // ==========================================================================

  /**
   * Create a Capsule for V2 authwit verification.
   */
  async createAuthwitCapsuleV2(
    call: FunctionCallInputV2,
    verifyingContract: Hex,
    contractAddress: AztecAddress,
    innerHash: bigint = 0n,
  ): Promise<Capsule> {
    const fc = this.buildFunctionCallV2(call);

    const typedData = this.encoder.buildAuthwitTypedData(
      fc,
      call.argTypes,
      verifyingContract,
    );

    const account = privateKeyToAccount(this.privateKey);
    const signature = await account.signTypedData(typedData);
    const sigBytes = hexToBytes(signature);
    const ecdsaSignature = sigBytes.slice(0, 64);

    // Get Merkle proof for authwit tree
    const proof = await getMerkleProof("Arguments", call.argTypes);

    const oracleData = this.buildAuthwitOracleDataV2(
      call,
      ecdsaSignature,
      proof,
      verifyingContract,
      innerHash,
    );

    const capsuleData = this.serializeAuthwitV2ToCapsule(oracleData);
    return new Capsule(
      contractAddress,
      new Fr(EIP712_AUTHWIT_V2_SLOT),
      capsuleData,
    );
  }

  private buildAuthwitOracleDataV2(
    call: FunctionCallInputV2,
    ecdsaSignature: Uint8Array,
    proof: MerkleProof,
    verifyingContract: Hex,
    innerHash: bigint,
  ): Eip712AuthwitOracleDataV2 {
    const sigBytes = new TextEncoder().encode(call.functionSignature);
    const functionSignature = new Uint8Array(MAX_SIGNATURE_SIZE_V2);
    functionSignature.set(sigBytes.slice(0, MAX_SIGNATURE_SIZE_V2));

    const functionArgs = [...call.args];
    while (functionArgs.length < MAX_SERIALIZED_ARGS_V2) {
      functionArgs.push(0n);
    }

    // Pre-computed type hash
    const fcAuthTypeHash = hexToBytes(computeFcTypeHashBytes("Arguments", call.argTypes));

    // Pre-computed authwit message hash
    const authwitDomainHash = Eip712EncoderV2.hashAuthwitAppDomain(
      this._chainId,
      verifyingContract,
    );
    const authwitMessageHash = hexToBytes(
      Eip712EncoderV2.hashFunctionCallAuthorization(
        authwitDomainHash,
        pad(toHex(call.targetAddress), { size: 32 }) as Hex,
        call.functionSignature,
        call.argTypes,
        call.args,
        call.isPublic ?? false,
      ),
    );

    return {
      ecdsaSignature,
      functionSignature,
      signatureLength: Math.min(sigBytes.length, MAX_SIGNATURE_SIZE_V2),
      functionArgs: functionArgs.slice(0, MAX_SERIALIZED_ARGS_V2),
      argsLength: Math.min(call.args.length, MAX_SERIALIZED_ARGS_V2),
      targetAddress: call.targetAddress,
      isPublic: call.isPublic ?? false,
      merkleProof: proof.siblingPath,
      merkleLeafIndex: proof.leafIndex,
      innerHash,
      fcAuthTypeHash,
      authwitMessageHash,
    };
  }

  /**
   * Serialize authwit witness to capsule fields (55 Fields).
   */
  private serializeAuthwitV2ToCapsule(data: Eip712AuthwitOracleDataV2): Fr[] {
    const fields: Fr[] = [];

    // [0-2]: Signature
    fields.push(...this.packBytes(data.ecdsaSignature, [31, 31, 2]));

    // [3-7]: Function signature
    fields.push(...this.packBytes(data.functionSignature, [31, 31, 31, 31, 4]));

    // [8]: Signature length
    fields.push(new Fr(data.signatureLength));

    // [9-28]: Function args
    for (let i = 0; i < MAX_SERIALIZED_ARGS_V2; i++) {
      fields.push(new Fr(data.functionArgs[i]));
    }

    // [29]: Args length
    fields.push(new Fr(data.argsLength));

    // [30]: Target address
    fields.push(new Fr(data.targetAddress));

    // [31]: is_public
    fields.push(new Fr(data.isPublic ? 1 : 0));

    // [32-48]: Merkle proof (MERKLE_DEPTH + padding to 17)
    for (let i = 0; i < MERKLE_DEPTH; i++) {
      fields.push(data.merkleProof[i]);
    }
    for (let i = MERKLE_DEPTH; i < 17; i++) {
      fields.push(Fr.ZERO);
    }

    // [49]: Merkle leaf index
    fields.push(new Fr(data.merkleLeafIndex));

    // [50-51]: fc_auth_type_hash (31+1)
    fields.push(...this.packBytes(data.fcAuthTypeHash, [31, 1]));

    // [52]: inner_hash
    fields.push(new Fr(data.innerHash));

    // [53-54]: authwit_message_hash (31+1)
    fields.push(...this.packBytes(data.authwitMessageHash, [31, 1]));

    return fields;
  }

  // ==========================================================================
  // Helpers
  // ==========================================================================

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

/**
 * Create a V2 EIP-712 account from a hex private key
 */
export function createEip712AccountV2(
  privateKey: Hex,
  chainId?: bigint,
): Eip712AccountV2 {
  return new Eip712AccountV2(privateKey, chainId);
}

/**
 * Generate a new random V2 EIP-712 account
 */
export function generateEip712AccountV2(chainId?: bigint): Eip712AccountV2 {
  return new Eip712AccountV2(undefined, chainId);
}
