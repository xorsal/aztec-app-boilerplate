/**
 * EIP-712 Encoder for Aztec Entrypoint Authorization
 *
 * Builds the EIP-712 typed data structure that matches what the Noir contract expects.
 * This encoder creates human-readable authorization requests for MetaMask signing.
 */

import { keccak256, encodePacked, concat, toHex, pad, type Hex } from "viem";
import {
  EIP712_TYPES_5,
  EMPTY_FUNCTION_CALL,
  ACCOUNT_MAX_CALLS,
  DEFAULT_VERIFYING_CONTRACT,
  MAX_SERIALIZED_ARGS,
  MAX_SIGNATURE_SIZE,
  type FunctionCall,
  type AppDomain,
  type AuthwitAppDomain,
  type EntrypointAuthorization5,
  type FunctionCallAuthorization,
} from "./eip712-types";

// Default app domain for EIP-712 Aztec Wallet
// NOTE: Salt must have a zero last byte because capsule serialization only packs 31 bytes
export const DEFAULT_APP_DOMAIN: AppDomain = {
  name: "EVM Aztec Wallet",
  version: "1.0.0",
  chainId: 31337n,
  salt: "0x0100000000000000000000000000000000000000000000000000000000000000",
};

// EIP-712 domain for outer Aztec rollup (with verifyingContract)
export const AZTEC_DOMAIN_WITH_CONTRACT = {
  name: "Aztec",
  version: "1",
  chainId: 31337n,
  verifyingContract: DEFAULT_VERIFYING_CONTRACT,
} as const;

// =============================================================================
// Type Hashes (pre-computed, must match Noir constants)
// =============================================================================

export const TYPE_HASHES = {
  // Note: selector is NOT included - it's derived from functionSignature via Poseidon2
  FUNCTION_CALL: keccak256(
    encodePacked(
      ["string"],
      [
        "FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)",
      ],
    ),
  ),
  APP_DOMAIN: keccak256(
    encodePacked(
      ["string"],
      ["AppDomain(string name,string version,uint256 chainId,bytes32 salt)"],
    ),
  ),
  ENTRYPOINT_AUTHORIZATION_5: keccak256(
    encodePacked(
      ["string"],
      [
        "EntrypointAuthorization(AppDomain appDomain,FunctionCall[5] functionCalls,uint256 txNonce)" +
          "AppDomain(string name,string version,uint256 chainId,bytes32 salt)" +
          "FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)",
      ],
    ),
  ),
  AUTHWIT_APP_DOMAIN: keccak256(
    encodePacked(
      ["string"],
      ["AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)"],
    ),
  ),
  FUNCTION_CALL_AUTHORIZATION: keccak256(
    encodePacked(
      ["string"],
      [
        "FunctionCallAuthorization(AuthwitAppDomain appDomain,FunctionCall functionCall)" +
          "AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)" +
          "FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)",
      ],
    ),
  ),
  EIP712_DOMAIN_WITH_CONTRACT: keccak256(
    encodePacked(
      ["string"],
      [
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
      ],
    ),
  ),
} as const;

// =============================================================================
// EIP-712 Encoder Class
// =============================================================================

export class Eip712Encoder {
  private appDomain: AppDomain;
  private chainId: bigint;

  constructor(options?: { appDomain?: Partial<AppDomain>; chainId?: bigint }) {
    this.chainId = options?.chainId ?? 31337n;
    this.appDomain = {
      ...DEFAULT_APP_DOMAIN,
      ...options?.appDomain,
      chainId: options?.appDomain?.chainId ?? this.chainId,
    };
  }

  /**
   * Build typed data for entrypoint authorization (5 function calls)
   */
  buildEntrypointTypedData5(
    functionCalls: FunctionCall[],
    txNonce: bigint,
    verifyingContract: Hex = DEFAULT_VERIFYING_CONTRACT,
  ): {
    types: typeof EIP712_TYPES_5;
    primaryType: "EntrypointAuthorization";
    domain: typeof AZTEC_DOMAIN_WITH_CONTRACT;
    message: EntrypointAuthorization5;
  } {
    // Pad to 5 calls
    const paddedCalls = [...functionCalls];
    while (paddedCalls.length < ACCOUNT_MAX_CALLS) {
      paddedCalls.push(EMPTY_FUNCTION_CALL);
    }
    if (paddedCalls.length > ACCOUNT_MAX_CALLS) {
      throw new Error(
        `Too many function calls: ${functionCalls.length} > ${ACCOUNT_MAX_CALLS}`,
      );
    }

    return {
      types: EIP712_TYPES_5,
      primaryType: "EntrypointAuthorization",
      domain: {
        ...AZTEC_DOMAIN_WITH_CONTRACT,
        chainId: this.chainId,
        verifyingContract,
      },
      message: {
        appDomain: this.appDomain,
        functionCalls: paddedCalls,
        txNonce,
      },
    };
  }

  /**
   * Build typed data for individual authwit (FunctionCallAuthorization)
   */
  buildAuthwitTypedData(
    functionCall: FunctionCall,
    verifyingContract: Hex,
  ): {
    types: typeof EIP712_TYPES_5;
    primaryType: "FunctionCallAuthorization";
    domain: typeof AZTEC_DOMAIN_WITH_CONTRACT;
    message: FunctionCallAuthorization;
  } {
    return {
      types: EIP712_TYPES_5,
      primaryType: "FunctionCallAuthorization",
      domain: {
        ...AZTEC_DOMAIN_WITH_CONTRACT,
        chainId: this.chainId,
        verifyingContract,
      },
      message: {
        appDomain: {
          chainId: this.chainId,
          verifyingContract: pad(verifyingContract, { size: 32 }),
        },
        functionCall,
      },
    };
  }

  /**
   * Create a function call from Aztec call details
   *
   * Note: selector is NOT included in FunctionCall - it's derived from functionSignature
   * via Poseidon2 hashing in the Noir contract. Signing the signature implicitly commits
   * to the selector.
   */
  static createFunctionCall(
    targetAddress: bigint | Hex,
    functionSignature: string,
    args: bigint[],
    isPrivate: boolean = true,
  ): FunctionCall {
    const contract =
      typeof targetAddress === "bigint"
        ? pad(toHex(targetAddress), { size: 32 })
        : pad(targetAddress as Hex, { size: 32 });

    if (args.length > MAX_SERIALIZED_ARGS) {
      throw new Error(
        `Too many arguments: ${args.length} > ${MAX_SERIALIZED_ARGS}`,
      );
    }

    if (functionSignature.length > MAX_SIGNATURE_SIZE) {
      throw new Error(
        `Function signature too long: ${functionSignature.length} > ${MAX_SIGNATURE_SIZE}`,
      );
    }

    return {
      contract,
      functionSignature,
      arguments: args,
      isPrivate,
    };
  }

  /**
   * Compute hashStruct(FunctionCall)
   *
   * Note: selector is NOT included in the hash - it's derived from functionSignature
   * via Poseidon2 hashing in the Noir contract.
   */
  static hashFunctionCall(call: FunctionCall): Hex {
    const sigHash = keccak256(
      encodePacked(["string"], [call.functionSignature]),
    );
    const argsEncoded =
      call.arguments.length > 0
        ? concat(call.arguments.map((arg) => pad(toHex(arg), { size: 32 })))
        : "0x";
    const argsHash = keccak256(argsEncoded);
    // EIP-712 bool encoding: 0 for false, 1 for true (as uint256)
    const isPrivateEncoded = pad(toHex(call.isPrivate ? 1n : 0n), { size: 32 });

    return keccak256(
      concat([
        TYPE_HASHES.FUNCTION_CALL,
        call.contract,
        sigHash,
        argsHash,
        isPrivateEncoded,
      ]),
    );
  }

  /**
   * Compute hashStruct(AppDomain)
   */
  static hashAppDomain(domain: AppDomain): Hex {
    const nameHash = keccak256(encodePacked(["string"], [domain.name]));
    const versionHash = keccak256(encodePacked(["string"], [domain.version]));

    return keccak256(
      concat([
        TYPE_HASHES.APP_DOMAIN,
        nameHash,
        versionHash,
        pad(toHex(domain.chainId), { size: 32 }),
        domain.salt,
      ]),
    );
  }

  /**
   * Hash an array of FunctionCall structs for EIP-712 encoding
   */
  static hashFunctionCallsArray(calls: FunctionCall[]): Hex {
    if (calls.length !== ACCOUNT_MAX_CALLS) {
      throw new Error(
        `Expected ${ACCOUNT_MAX_CALLS} calls, got ${calls.length}`,
      );
    }
    const hashes = calls.map((call) => Eip712Encoder.hashFunctionCall(call));
    return keccak256(concat(hashes));
  }

  /**
   * Compute hashStruct(EntrypointAuthorization) - 5 function calls
   */
  static hashEntrypointAuthorization5(
    appDomain: AppDomain,
    functionCalls: FunctionCall[],
    txNonce: bigint,
  ): Hex {
    return keccak256(
      concat([
        TYPE_HASHES.ENTRYPOINT_AUTHORIZATION_5,
        Eip712Encoder.hashAppDomain(appDomain),
        Eip712Encoder.hashFunctionCallsArray(functionCalls),
        pad(toHex(txNonce), { size: 32 }),
      ]),
    );
  }

  /**
   * Compute hashStruct(AuthwitAppDomain)
   */
  static hashAuthwitAppDomain(chainId: bigint, verifyingContract: Hex): Hex {
    return keccak256(
      concat([
        TYPE_HASHES.AUTHWIT_APP_DOMAIN,
        pad(toHex(chainId), { size: 32 }),
        pad(verifyingContract, { size: 32 }),
      ]),
    );
  }

  /**
   * Compute hashStruct(FunctionCallAuthorization)
   */
  static hashFunctionCallAuthorization(
    authwitDomain: AuthwitAppDomain,
    functionCall: FunctionCall,
  ): Hex {
    return keccak256(
      concat([
        TYPE_HASHES.FUNCTION_CALL_AUTHORIZATION,
        Eip712Encoder.hashAuthwitAppDomain(
          authwitDomain.chainId,
          authwitDomain.verifyingContract,
        ),
        Eip712Encoder.hashFunctionCall(functionCall),
      ]),
    );
  }

  /**
   * Compute domain separator with verifyingContract
   */
  static computeDomainSeparatorWithContract(
    chainId: bigint,
    verifyingContract: Hex,
  ): Hex {
    return keccak256(
      concat([
        TYPE_HASHES.EIP712_DOMAIN_WITH_CONTRACT,
        keccak256(encodePacked(["string"], [AZTEC_DOMAIN_WITH_CONTRACT.name])),
        keccak256(
          encodePacked(["string"], [AZTEC_DOMAIN_WITH_CONTRACT.version]),
        ),
        pad(toHex(chainId), { size: 32 }),
        pad(verifyingContract, { size: 32 }),
      ]),
    );
  }

  /**
   * Compute final EIP-712 payload (what gets signed)
   */
  static computeEip712Payload(domainSeparator: Hex, messageHash: Hex): Hex {
    return keccak256(concat(["0x1901", domainSeparator, messageHash]));
  }

  /**
   * Get pre-computed hashes for Noir constants
   */
  static getNoirConstants(): {
    appDomainNameHash: Hex;
    appDomainVersionHash: Hex;
    domainSeparator: Hex;
  } {
    return {
      appDomainNameHash: keccak256(
        encodePacked(["string"], [DEFAULT_APP_DOMAIN.name]),
      ),
      appDomainVersionHash: keccak256(
        encodePacked(["string"], [DEFAULT_APP_DOMAIN.version]),
      ),
      domainSeparator: Eip712Encoder.computeDomainSeparatorWithContract(
        31337n,
        DEFAULT_VERIFYING_CONTRACT,
      ),
    };
  }
}
