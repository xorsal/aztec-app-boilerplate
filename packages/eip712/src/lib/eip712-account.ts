/**
 * EIP-712 Account Contract Implementation
 *
 * This account uses EIP-712 typed data signing for human-readable
 * authorization requests via MetaMask/Ethereum wallets.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, type Hex, hexToBytes, bytesToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Eip712Encoder, DEFAULT_APP_DOMAIN } from "./eip712-encoder";
import {
  type FunctionCall,
  ACCOUNT_MAX_CALLS,
  EIP712_WITNESS_5_SLOT,
  EIP712_AUTHWIT_SLOT,
  MAX_SIGNATURE_SIZE,
  MAX_SERIALIZED_ARGS,
  DEFAULT_VERIFYING_CONTRACT,
  EMPTY_FUNCTION_CALL,
} from "./eip712-types";
import { Capsule } from "@aztec/stdlib/tx";
import { Fr } from "@aztec/aztec.js/fields";
import { AztecAddress } from "@aztec/aztec.js/addresses";

// =============================================================================
// Re-export constants
// =============================================================================

export { MAX_SIGNATURE_SIZE, MAX_SERIALIZED_ARGS, ACCOUNT_MAX_CALLS };

// =============================================================================
// Types
// =============================================================================

/** Oracle data for 5-call entrypoint */
export interface Eip712OracleData5 {
  ecdsaSignature: Uint8Array; // 64 bytes (r || s) - shared
  functionSignatures: Uint8Array[]; // [5][MAX_SIGNATURE_SIZE]
  signatureLengths: number[]; // [5]
  functionArgs: bigint[][]; // [5][MAX_SERIALIZED_ARGS]
  argsLengths: number[]; // [5]
  targetAddresses: bigint[]; // [5]
  chainId: bigint;
  salt: Uint8Array; // 32 bytes
}

/** Oracle data for individual authwit */
export interface Eip712AuthwitOracleData {
  ecdsaSignature: Uint8Array; // 64 bytes (r || s)
  functionSignature: Uint8Array; // [MAX_SIGNATURE_SIZE]
  signatureLength: number;
  functionArgs: bigint[]; // [MAX_SERIALIZED_ARGS]
  argsLength: number;
  targetAddress: bigint;
  chainId: bigint;
  verifyingContract: bigint;
  innerHash: bigint;
}

export interface FunctionCallInput {
  targetAddress: bigint;
  functionSignature: string;
  args: bigint[];
  /** If true, this is a public function and args_hash should include the selector */
  isPublic?: boolean;
}

// =============================================================================
// EIP-712 Account Class
// =============================================================================

/**
 * Account class that handles EIP-712 signing for Aztec transactions.
 *
 * This class:
 * 1. Generates/stores the ECDSA private key
 * 2. Creates EIP-712 typed data for signing
 * 3. Produces the capsule data needed by the Noir contract
 */
export class Eip712Account {
  private privateKey: Hex;
  private publicKeyX: Uint8Array;
  private publicKeyY: Uint8Array;
  private encoder: Eip712Encoder;
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
    this.encoder = new Eip712Encoder({ chainId });
  }

  /**
   * Get the chain ID used for EIP-712 domain
   */
  get chainId(): bigint {
    return this._chainId;
  }

  /**
   * Get the public key components for contract initialization
   */
  getPublicKey(): { x: Uint8Array; y: Uint8Array } {
    return {
      x: this.publicKeyX,
      y: this.publicKeyY,
    };
  }

  /**
   * Get public key as arrays of numbers (for contract constructor)
   */
  getPublicKeyArrays(): { x: number[]; y: number[] } {
    return {
      x: Array.from(this.publicKeyX),
      y: Array.from(this.publicKeyY),
    };
  }

  /**
   * Get the Ethereum address derived from the public key
   */
  getEthAddress(): Hex {
    const pubKeyBytes = new Uint8Array(64);
    pubKeyBytes.set(this.publicKeyX, 0);
    pubKeyBytes.set(this.publicKeyY, 32);
    const hash = keccak256(pubKeyBytes);
    return `0x${hash.slice(-40)}` as Hex;
  }

  // ==========================================================================
  // 5-Call Entrypoint Methods
  // ==========================================================================

  /**
   * Sign an entrypoint authorization for up to 5 function calls.
   * Empty slots are padded with EMPTY_FUNCTION_CALL.
   */
  async signEntrypoint5(
    calls: FunctionCallInput[],
    txNonce: bigint,
    verifyingContract: Hex = DEFAULT_VERIFYING_CONTRACT,
    salt: Hex = DEFAULT_APP_DOMAIN.salt,
  ): Promise<Eip712OracleData5> {
    if (calls.length > ACCOUNT_MAX_CALLS) {
      throw new Error(`Too many calls: ${calls.length} > ${ACCOUNT_MAX_CALLS}`);
    }

    // Convert inputs to FunctionCall format and pad to 5
    // isPrivate is the inverse of isPublic
    // Note: selector is NOT included - it's derived from functionSignature via Poseidon2
    const functionCalls: FunctionCall[] = calls.map((call) =>
      Eip712Encoder.createFunctionCall(
        call.targetAddress,
        call.functionSignature,
        call.args,
        !call.isPublic, // isPrivate = !isPublic
      ),
    );
    while (functionCalls.length < ACCOUNT_MAX_CALLS) {
      functionCalls.push(EMPTY_FUNCTION_CALL);
    }

    // Build typed data for 5 calls
    const typedData = this.encoder.buildEntrypointTypedData5(
      functionCalls,
      txNonce,
      verifyingContract,
    );

    // Sign using viem's account
    const account = privateKeyToAccount(this.privateKey);
    const signature = await account.signTypedData(typedData);

    // Parse signature (remove v, keep r || s)
    const sigBytes = hexToBytes(signature);
    const ecdsaSignature = sigBytes.slice(0, 64);

    return this.buildOracleData5(
      calls,
      typedData.domain.chainId as bigint,
      hexToBytes(salt),
      ecdsaSignature,
    );
  }

  /**
   * Build oracle data for 5 function calls.
   */
  private buildOracleData5(
    calls: FunctionCallInput[],
    chainId: bigint,
    salt: Uint8Array,
    ecdsaSignature: Uint8Array,
  ): Eip712OracleData5 {
    const functionSignatures: Uint8Array[] = [];
    const signatureLengths: number[] = [];
    const functionArgs: bigint[][] = [];
    const argsLengths: number[] = [];
    const targetAddresses: bigint[] = [];

    // Process each call (pad to ACCOUNT_MAX_CALLS)
    for (let i = 0; i < ACCOUNT_MAX_CALLS; i++) {
      const call =
        i < calls.length
          ? calls[i]
          : {
              targetAddress: 0n,
              functionSignature: "",
              args: [],
              isPublic: false,
            };

      // Function signature as bytes
      const sigBytes = new TextEncoder().encode(call.functionSignature);
      const funcSig = new Uint8Array(MAX_SIGNATURE_SIZE);
      funcSig.set(sigBytes.slice(0, MAX_SIGNATURE_SIZE));
      functionSignatures.push(funcSig);
      signatureLengths.push(Math.min(sigBytes.length, MAX_SIGNATURE_SIZE));

      // Function args (padded)
      let args: bigint[] = [...call.args];
      while (args.length < MAX_SERIALIZED_ARGS) {
        args.push(0n);
      }
      functionArgs.push(args.slice(0, MAX_SERIALIZED_ARGS));
      argsLengths.push(Math.min(call.args.length, MAX_SERIALIZED_ARGS));

      targetAddresses.push(call.targetAddress);
    }

    return {
      ecdsaSignature,
      functionSignatures,
      signatureLengths,
      functionArgs,
      argsLengths,
      targetAddresses,
      chainId,
      salt,
    };
  }

  /**
   * Create a Capsule for 5-call entrypoint.
   *
   * @param calls - 1-5 function calls to authorize
   * @param txNonce - Transaction nonce (must match app_payload.tx_nonce)
   * @param contractAddress - The account contract address
   * @param verifyingContract - Optional verifying contract (defaults to sandbox rollup)
   * @param salt - Optional salt for EIP-712 domain
   */
  async createWitnessCapsule5(
    calls: FunctionCallInput[],
    txNonce: bigint,
    contractAddress: AztecAddress,
    verifyingContract: Hex = DEFAULT_VERIFYING_CONTRACT,
    salt: Hex = DEFAULT_APP_DOMAIN.salt,
  ): Promise<Capsule> {
    const oracleData = await this.signEntrypoint5(
      calls,
      txNonce,
      verifyingContract,
      salt,
    );
    const capsuleData = this.serializeWitness5ToCapsule(oracleData);
    return new Capsule(
      contractAddress,
      new Fr(EIP712_WITNESS_5_SLOT),
      capsuleData,
    );
  }

  /**
   * Create a Capsule for 5-call entrypoint using an external signature.
   * This is used when signing with MetaMask instead of the local private key.
   *
   * @param calls - 1-5 function calls to authorize
   * @param txNonce - Transaction nonce (must match app_payload.tx_nonce)
   * @param externalSignature - The 64-byte ECDSA signature (r || s) from external signer
   * @param contractAddress - The account contract address
   * @param verifyingContract - Optional verifying contract (defaults to sandbox rollup)
   * @param salt - Optional salt for EIP-712 domain
   */
  createWitnessCapsule5WithExternalSignature(
    calls: FunctionCallInput[],
    txNonce: bigint,
    externalSignature: Uint8Array,
    contractAddress: AztecAddress,
    verifyingContract: Hex = DEFAULT_VERIFYING_CONTRACT,
    salt: Hex = DEFAULT_APP_DOMAIN.salt,
  ): Capsule {
    if (externalSignature.length !== 64) {
      throw new Error(
        `Invalid signature length: ${externalSignature.length}, expected 64`,
      );
    }

    // Build oracle data with external signature
    const oracleData = this.buildOracleData5(
      calls,
      this.chainId,
      hexToBytes(salt),
      externalSignature,
    );
    const capsuleData = this.serializeWitness5ToCapsule(oracleData);
    return new Capsule(
      contractAddress,
      new Fr(EIP712_WITNESS_5_SLOT),
      capsuleData,
    );
  }

  /**
   * Serialize Eip712OracleData5 to capsule data format (145 Fields).
   *
   * Note: selector is NOT included - it's derived from functionSignature via Poseidon2
   */
  private serializeWitness5ToCapsule(data: Eip712OracleData5): Fr[] {
    const fields: Fr[] = [];

    // [0-2]: Signature (64 bytes -> 3 fields: 31+31+2)
    fields.push(...this.packBytes(data.ecdsaSignature, [31, 31, 2]));

    // [3-142]: 5 calls, each 28 fields
    for (let callIdx = 0; callIdx < ACCOUNT_MAX_CALLS; callIdx++) {
      // Function signature (128 bytes -> 5 fields: 31+31+31+31+4)
      fields.push(
        ...this.packBytes(
          data.functionSignatures[callIdx],
          [31, 31, 31, 31, 4],
        ),
      );

      // Signature length
      fields.push(new Fr(data.signatureLengths[callIdx]));

      // Function args (20 fields)
      for (let i = 0; i < MAX_SERIALIZED_ARGS; i++) {
        fields.push(new Fr(data.functionArgs[callIdx][i]));
      }

      // Args length
      fields.push(new Fr(data.argsLengths[callIdx]));

      // Target address
      fields.push(new Fr(data.targetAddresses[callIdx]));
    }

    // [143]: chain_id
    fields.push(new Fr(data.chainId));

    // [144]: salt (first 31 bytes)
    fields.push(this.packBytes(data.salt, [31])[0]);

    return fields;
  }

  // ==========================================================================
  // Individual Authwit Methods
  // ==========================================================================

  /**
   * Sign an individual authorization (authwit) for a single function call.
   * Used by verify_private_authwit.
   *
   * Note: selector is NOT included in EIP-712 - it's derived from functionSignature via Poseidon2
   */
  async signAuthwit(
    call: FunctionCallInput,
    verifyingContract: Hex,
    innerHash: bigint = 0n,
  ): Promise<Eip712AuthwitOracleData> {
    // Convert to FunctionCall format
    // isPrivate is the inverse of isPublic
    const functionCall = Eip712Encoder.createFunctionCall(
      call.targetAddress,
      call.functionSignature,
      call.args,
      !call.isPublic, // isPrivate = !isPublic
    );

    // Build typed data
    const typedData = this.encoder.buildAuthwitTypedData(
      functionCall,
      verifyingContract,
    );

    // Sign using viem's account
    const account = privateKeyToAccount(this.privateKey);
    const signature = await account.signTypedData(typedData);

    // Parse signature
    const sigBytes = hexToBytes(signature);
    const ecdsaSignature = sigBytes.slice(0, 64);

    // Build oracle data
    const sigBytesEncoded = new TextEncoder().encode(call.functionSignature);
    const functionSignature = new Uint8Array(MAX_SIGNATURE_SIZE);
    functionSignature.set(sigBytesEncoded.slice(0, MAX_SIGNATURE_SIZE));

    const functionArgs = [...call.args];
    while (functionArgs.length < MAX_SERIALIZED_ARGS) {
      functionArgs.push(0n);
    }

    return {
      ecdsaSignature,
      functionSignature,
      signatureLength: Math.min(sigBytesEncoded.length, MAX_SIGNATURE_SIZE),
      functionArgs: functionArgs.slice(0, MAX_SERIALIZED_ARGS),
      argsLength: Math.min(call.args.length, MAX_SERIALIZED_ARGS),
      targetAddress: call.targetAddress,
      chainId: typedData.domain.chainId as bigint,
      verifyingContract: BigInt(verifyingContract),
      innerHash,
    };
  }

  /**
   * Create a Capsule for individual authwit verification.
   */
  async createAuthwitCapsule(
    call: FunctionCallInput,
    verifyingContract: Hex,
    contractAddress: AztecAddress,
    innerHash: bigint = 0n,
  ): Promise<Capsule> {
    const oracleData = await this.signAuthwit(
      call,
      verifyingContract,
      innerHash,
    );
    const capsuleData = this.serializeAuthwitToCapsule(oracleData);
    return new Capsule(
      contractAddress,
      new Fr(EIP712_AUTHWIT_SLOT),
      capsuleData,
    );
  }

  /**
   * Serialize Eip712AuthwitOracleData to capsule data format (34 Fields).
   */
  private serializeAuthwitToCapsule(data: Eip712AuthwitOracleData): Fr[] {
    const fields: Fr[] = [];

    // [0-2]: Signature
    fields.push(...this.packBytes(data.ecdsaSignature, [31, 31, 2]));

    // [3-7]: Function signature
    fields.push(...this.packBytes(data.functionSignature, [31, 31, 31, 31, 4]));

    // [8]: Signature length
    fields.push(new Fr(data.signatureLength));

    // [9-28]: Function args
    for (let i = 0; i < MAX_SERIALIZED_ARGS; i++) {
      fields.push(new Fr(data.functionArgs[i]));
    }

    // [29]: Args length
    fields.push(new Fr(data.argsLength));

    // [30]: Target address
    fields.push(new Fr(data.targetAddress));

    // [31]: Chain ID
    fields.push(new Fr(data.chainId));

    // [32]: Verifying contract
    fields.push(new Fr(data.verifyingContract));

    // [33]: Inner hash
    fields.push(new Fr(data.innerHash));

    return fields;
  }

  /**
   * Pack bytes into Fr fields (big-endian, up to 31 bytes per field)
   */
  private packBytes(bytes: Uint8Array, bytesPerField: number[]): Fr[] {
    const fields: Fr[] = [];
    let offset = 0;

    for (const size of bytesPerField) {
      const chunk = bytes.slice(offset, offset + size);
      // Convert chunk to bigint (big-endian)
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
 * Create an EIP-712 account from a hex private key
 */
export function createEip712Account(
  privateKey: Hex,
  chainId?: bigint,
): Eip712Account {
  return new Eip712Account(privateKey, chainId);
}

/**
 * Generate a new random EIP-712 account
 */
export function generateEip712Account(chainId?: bigint): Eip712Account {
  return new Eip712Account(undefined, chainId);
}
