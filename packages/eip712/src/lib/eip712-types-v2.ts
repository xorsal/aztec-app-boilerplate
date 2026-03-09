/**
 * EIP-712 V2 Types for Aztec Authwits
 *
 * V2 introduces variable argument types: each argument can be bytes32, uint256,
 * or address (instead of the fixed uint256[] in V1). This enables human-readable
 * display in MetaMask (e.g., addresses as address hex instead of uint256 decimals).
 *
 * The argument names are fixed (argument1, argument2, ...) — only types are variable.
 * A Merkle tree whitelist constrains valid type_hash(Arguments{N}) values.
 *
 * Per-slot design: Each call slot has its own FunctionCall{N} and Arguments{N} types.
 */

import type { Hex } from "viem";

// =============================================================================
// Allowed argument types
// =============================================================================

/** Allowed EIP-712 types for each argument position */
export type ArgumentType = "bytes32" | "uint256" | "address";

/** All allowed argument types */
export const ARGUMENT_TYPES: ArgumentType[] = [
  "bytes32",
  "uint256",
  "address",
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

/** Max function calls per V2 entrypoint */
export const MAX_ENTRYPOINT_CALLS = 4;

/** Max arguments per function call in EIP-712 type definitions (must match Merkle tree generator MAX_ARGS) */
export const MAX_ARGS_V2 = 5;

/** Max EIP-712 argument types covered by the Merkle tree (alias for clarity) */
export const MERKLE_MAX_ARGS = MAX_ARGS_V2;

/** Max function arguments (same as V1, for Aztec compatibility) */
export const MAX_SERIALIZED_ARGS_V2 = 20;

/** Max function signature string length (same as V1) */
export const MAX_SIGNATURE_SIZE_V2 = 128;

/** Max Arguments type string length (e.g. "Arguments1(bytes32 argument1,uint256 argument2,...address argument5)") */
export const MAX_ARGS_TYPE_STRING_LEN = 256;

/** Merkle tree depth for Arguments whitelist (2^9 = 512 leaves) */
export const MERKLE_DEPTH = 9;

// =============================================================================
// Capsule Slots (must match Noir eip712_v2.nr)
// =============================================================================

/** Capsule slots for V2 per-call-count entrypoint witnesses */
export const EIP712_WITNESS_V2_SLOTS: Record<number, bigint> = {
  1: 0x1234567890abcdf1n,
  2: 0x1234567890abcdf2n,
  3: 0x1234567890abcdf3n,
  4: 0x1234567890abcdf4n,
};

/** Capsule slot for V2 individual authwit */
export const EIP712_AUTHWIT_V2_SLOT = 0xabcdef1234567891n;

// =============================================================================
// EIP-712 Type Definitions (static parts)
// =============================================================================

/**
 * Build the Arguments type definition for a given arg types.
 * E.g. buildArgumentsTypeDef(["bytes32", "uint256"]) returns:
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
 * Fixed EIP-712 type definitions for V2.
 * EntrypointAuthorization and per-slot FunctionCall/Arguments types are added dynamically.
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

  // AuthwitAppDomain (same as V1)
  AuthwitAppDomain: [
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "bytes32" },
  ],

  // FunctionCallAuthorization with variable Arguments (authwit, unnumbered)
  FunctionCallAuthorization: [
    { name: "appDomain", type: "AuthwitAppDomain" },
    { name: "contract", type: "bytes32" },
    { name: "functionSignature", type: "string" },
    { name: "arguments", type: "Arguments" },
    { name: "isPublic", type: "bool" },
  ],
};

/**
 * Build complete EIP-712 types for per-call-count entrypoint with per-slot argument types.
 * Each call gets its own FunctionCall{N} and Arguments{N} type.
 */
export function buildEntrypointTypes(
  perCallArgTypes: ArgumentType[][],
): Record<string, Array<{ name: string; type: string }>> {
  const callCount = perCallArgTypes.length;

  const entrypointFields = [
    { name: "accountData", type: "AccountData" },
    ...Array.from({ length: callCount }, (_, i) => ({
      name: `functionCall${i + 1}`,
      type: `FunctionCall${i + 1}`,
    })),
    { name: "txMetadata", type: "TxMetadata" },
  ];

  const result: Record<string, Array<{ name: string; type: string }>> = {
    ...EIP712_TYPES_V2_BASE,
    EntrypointAuthorization: entrypointFields,
  };

  for (let i = 0; i < callCount; i++) {
    const n = i + 1;
    result[`FunctionCall${n}`] = [
      { name: "contract", type: "bytes32" },
      { name: "functionSignature", type: "string" },
      { name: "arguments", type: `Arguments${n}` },
      { name: "isPublic", type: "bool" },
      { name: "hideMsgSender", type: "bool" },
      { name: "isStatic", type: "bool" },
    ];
    result[`Arguments${n}`] = buildArgumentsTypeDef(perCallArgTypes[i]);
  }

  return result;
}

/**
 * Build complete EIP-712 types for authwit with dynamic argument types.
 * Authwit uses unnumbered "Arguments" and "FunctionCallAuthorization".
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

/** Per-slot FunctionCall primary struct definitions (all 124 chars) */
export const FC_PRIMARIES: Record<number, string> = {
  1: "FunctionCall1(bytes32 contract,string functionSignature,Arguments1 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
  2: "FunctionCall2(bytes32 contract,string functionSignature,Arguments2 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
  3: "FunctionCall3(bytes32 contract,string functionSignature,Arguments3 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
  4: "FunctionCall4(bytes32 contract,string functionSignature,Arguments4 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
};

/**
 * Build the EntrypointAuthorization primary string for N calls.
 */
export function buildEntrypointAuthPrimary(callCount: number): string {
  const fcFields = Array.from(
    { length: callCount },
    (_, i) => `FunctionCall${i + 1} functionCall${i + 1}`,
  ).join(",");
  return `EntrypointAuthorization(AccountData accountData,${fcFields},TxMetadata txMetadata)`;
}

/** FunctionCallAuthorization primary struct definition (authwit, unchanged) */
export const FC_AUTH_PRIMARY =
  "FunctionCallAuthorization(AuthwitAppDomain appDomain,bytes32 contract,string functionSignature,Arguments arguments,bool isPublic)";

/** AuthwitAppDomain type definition (referenced by FunctionCallAuthorization) */
export const AUTHWIT_APP_DOMAIN_DEF =
  "AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)";

// =============================================================================
// Default verifying contract (sandbox rollup address)
// =============================================================================

export const DEFAULT_VERIFYING_CONTRACT_V2 =
  "0x0000000000000000000000000000000000000001" as const;
