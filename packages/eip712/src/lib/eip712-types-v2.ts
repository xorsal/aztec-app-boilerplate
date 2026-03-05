/**
 * EIP-712 V2 Types for Aztec Authwits
 *
 * V2 introduces variable argument types: each argument can be bytes32, uint256,
 * or int256 (instead of the fixed uint256[] in V1). This enables human-readable
 * display in MetaMask (e.g., addresses as bytes32 hex instead of uint256 decimals).
 *
 * The argument names are fixed (argument1, argument2, ...) — only types are variable.
 * A Merkle tree whitelist constrains valid type_hash(Arguments{N}) values.
 */

import type { Hex } from "viem";

// =============================================================================
// Allowed argument types
// =============================================================================

/** Allowed EIP-712 types for each argument position */
export type ArgumentType = "bytes32" | "uint256" | "int256";

/** All allowed argument types */
export const ARGUMENT_TYPES: ArgumentType[] = [
  "bytes32",
  "uint256",
  "int256",
];

// =============================================================================
// V2 Struct Interfaces
// =============================================================================

/**
 * Account data included in entrypoint authorization.
 * Provides wallet identification for clear signing display.
 */
export interface AccountData {
  address: Hex; // bytes32 - account contract address
  walletName: string; // "EVM Aztec Wallet"
  version: string; // "1.0.0"
}

/**
 * Transaction metadata
 */
export interface TxMetadata {
  feePaymentMethod: number; // uint8
  cancellable: boolean;
  txNonce: bigint; // uint256
}

/**
 * V2 function call with variable argument types.
 * Arguments are individual typed fields instead of uint256[].
 */
export interface FunctionCallV2 {
  contract: Hex; // bytes32 - target_address as 32 bytes
  functionSignature: string; // Full signature e.g. "transfer_private(Field,Field,u128,Field)"
  arguments: Record<string, bigint>; // {argument1: value, argument2: value, ...}
  isPublic: boolean;
  hideMsgSender: boolean;
  isStatic: boolean;
}

/**
 * Authwit app domain (same as V1)
 */
export interface AuthwitAppDomainV2 {
  chainId: bigint;
  verifyingContract: Hex; // bytes32
}

/**
 * Entrypoint authorization message (2 calls)
 */
export interface EntrypointAuthorizationV2 {
  accountData: AccountData;
  functionCall1: FunctionCallV2;
  functionCall2: FunctionCallV2;
  txMetadata: TxMetadata;
}

/**
 * Individual function call authorization (authwit)
 */
export interface FunctionCallAuthorizationV2 {
  appDomain: AuthwitAppDomainV2;
  contract: Hex;
  functionSignature: string;
  arguments: Record<string, bigint>;
  isPublic: boolean;
}

// =============================================================================
// V2 Constants
// =============================================================================

/** Max function calls per V2 entrypoint (reduced from 5 to 2) */
export const ACCOUNT_MAX_CALLS_V2 = 2;

/** Max arguments per function call */
export const MAX_ARGS_V2 = 10;

/** Max function arguments (same as V1, for Aztec compatibility) */
export const MAX_SERIALIZED_ARGS_V2 = 20;

/** Max function signature string length (same as V1) */
export const MAX_SIGNATURE_SIZE_V2 = 128;

/** Max Arguments type string length (e.g. "Arguments1(bytes32 argument1,uint256 argument2,...int256 argument10)") */
export const MAX_ARGS_TYPE_STRING_LEN = 256;

/** Merkle tree depth for Arguments whitelist (2^17 = 131072 leaves) */
export const MERKLE_DEPTH = 17;

// =============================================================================
// Capsule Slots (must match Noir eip712_v2.nr)
// =============================================================================

/** Capsule slot for V2 2-call entrypoint witness */
export const EIP712_WITNESS_V2_2_SLOT = 0x1234567890abcdf1n;

/** Capsule slot for V2 individual authwit */
export const EIP712_AUTHWIT_V2_SLOT = 0xabcdef1234567891n;

// =============================================================================
// EIP-712 Type Definitions (static parts)
// =============================================================================

/**
 * Build the Arguments type definition for a given struct name and arg types.
 * E.g. buildArgumentsTypeDef("Arguments1", ["bytes32", "uint256"]) returns:
 * [{name: "argument1", type: "bytes32"}, {name: "argument2", type: "uint256"}]
 */
export function buildArgumentsTypeDef(
  argTypes: ArgumentType[],
): Array<{ name: string; type: string }> {
  return argTypes.map((type, i) => ({
    name: `argument${i + 1}`,
    type,
  }));
}

/**
 * Build the Arguments type string for keccak256 hashing.
 * E.g. buildArgumentsTypeString("Arguments1", ["bytes32", "uint256"]) returns:
 * "Arguments1(bytes32 argument1,uint256 argument2)"
 */
export function buildArgumentsTypeString(
  structName: string,
  argTypes: ArgumentType[],
): string {
  if (argTypes.length === 0) {
    return `${structName}()`;
  }
  const fields = argTypes
    .map((type, i) => `${type} argument${i + 1}`)
    .join(",");
  return `${structName}(${fields})`;
}

/**
 * Fixed EIP-712 type definitions for V2 (2-call entrypoint).
 * Arguments1 and Arguments2 types are added dynamically at signing time.
 */
export const EIP712_TYPES_V2_BASE = {
  EIP712Domain: [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "address" },
  ],

  AccountData: [
    { name: "address", type: "bytes32" },
    { name: "walletName", type: "string" },
    { name: "version", type: "string" },
  ],

  TxMetadata: [
    { name: "feePaymentMethod", type: "uint8" },
    { name: "cancellable", type: "bool" },
    { name: "txNonce", type: "uint256" },
  ],

  EntrypointAuthorization: [
    { name: "accountData", type: "AccountData" },
    { name: "functionCall1", type: "FunctionCall1" },
    { name: "functionCall2", type: "FunctionCall2" },
    { name: "txMetadata", type: "TxMetadata" },
  ],

  FunctionCall1: [
    { name: "contract", type: "bytes32" },
    { name: "functionSignature", type: "string" },
    { name: "arguments", type: "Arguments1" },
    { name: "isPublic", type: "bool" },
    { name: "hideMsgSender", type: "bool" },
    { name: "isStatic", type: "bool" },
  ],

  FunctionCall2: [
    { name: "contract", type: "bytes32" },
    { name: "functionSignature", type: "string" },
    { name: "arguments", type: "Arguments2" },
    { name: "isPublic", type: "bool" },
    { name: "hideMsgSender", type: "bool" },
    { name: "isStatic", type: "bool" },
  ],

  // AuthwitAppDomain (same as V1)
  AuthwitAppDomain: [
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "bytes32" },
  ],

  // FunctionCallAuthorization with variable Arguments
  FunctionCallAuthorization: [
    { name: "appDomain", type: "AuthwitAppDomain" },
    { name: "contract", type: "bytes32" },
    { name: "functionSignature", type: "string" },
    { name: "arguments", type: "Arguments" },
    { name: "isPublic", type: "bool" },
  ],
};

/**
 * Build complete EIP-712 types for 2-call entrypoint with dynamic argument types.
 */
export function buildEntrypointTypes(
  args1Types: ArgumentType[],
  args2Types: ArgumentType[],
): Record<string, Array<{ name: string; type: string }>> {
  return {
    ...EIP712_TYPES_V2_BASE,
    Arguments1: buildArgumentsTypeDef(args1Types),
    Arguments2: buildArgumentsTypeDef(args2Types),
  };
}

/**
 * Build complete EIP-712 types for authwit with dynamic argument types.
 */
export function buildAuthwitTypes(
  argTypes: ArgumentType[],
): Record<string, Array<{ name: string; type: string }>> {
  return {
    ...EIP712_TYPES_V2_BASE,
    Arguments: buildArgumentsTypeDef(argTypes),
  };
}

// =============================================================================
// Primary Struct Strings (hardcoded, for constraining in Noir)
// =============================================================================

/** EntrypointAuthorization primary struct definition */
export const ENTRYPOINT_AUTH_PRIMARY =
  "EntrypointAuthorization(AccountData accountData,FunctionCall1 functionCall1,FunctionCall2 functionCall2,TxMetadata txMetadata)";

/** FunctionCall1 primary struct definition */
export const FC1_PRIMARY =
  "FunctionCall1(bytes32 contract,string functionSignature,Arguments1 arguments,bool isPublic,bool hideMsgSender,bool isStatic)";

/** FunctionCall2 primary struct definition */
export const FC2_PRIMARY =
  "FunctionCall2(bytes32 contract,string functionSignature,Arguments2 arguments,bool isPublic,bool hideMsgSender,bool isStatic)";

/** FunctionCallAuthorization primary struct definition */
export const FC_AUTH_PRIMARY =
  "FunctionCallAuthorization(AuthwitAppDomain appDomain,bytes32 contract,string functionSignature,Arguments arguments,bool isPublic)";

/** AuthwitAppDomain type definition (referenced by FunctionCallAuthorization) */
export const AUTHWIT_APP_DOMAIN_DEF =
  "AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)";

// =============================================================================
// Empty function call (for padding unused slots in 2-call entrypoint)
// =============================================================================

export const EMPTY_FUNCTION_CALL_V2: FunctionCallV2 = {
  contract:
    "0x0000000000000000000000000000000000000000000000000000000000000000",
  functionSignature: "",
  arguments: {},
  isPublic: false,
  hideMsgSender: false,
  isStatic: false,
};

// =============================================================================
// Default verifying contract (sandbox rollup address)
// =============================================================================

export const DEFAULT_VERIFYING_CONTRACT_V2 =
  "0x0000000000000000000000000000000000000001" as const;
