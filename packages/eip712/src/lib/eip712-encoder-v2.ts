/**
 * EIP-712 V2 Encoder for Aztec Entrypoint Authorization
 *
 * Builds the EIP-712 typed data structure for the V2 contract with:
 * - Variable argument types (bytes32, uint256, int256 per argument)
 * - Per-slot FunctionCall{N} and Arguments{N} types
 * - AccountData and TxMetadata sub-structs
 * - Merkle tree whitelist for Arguments type hashes
 */

import { keccak256, encodePacked, concat, toHex, pad, type Hex } from "viem";
import {
  type ArgumentType,
  type AccountData,
  type TxMetadata,
  type FunctionCallV2,
  DEFAULT_VERIFYING_CONTRACT_V2,
  FC_PRIMARIES,
  FC_AUTH_PRIMARY,
  buildEntrypointAuthPrimary,
  buildArgumentsTypeString,
  buildEntrypointTypes,
  buildAuthwitTypes,
} from "./eip712-types-v2.js";

// =============================================================================
// Default configurations
// =============================================================================

export const DEFAULT_ACCOUNT_DATA: AccountData = {
  address:
    "0x0000000000000000000000000000000000000000000000000000000000000000",
  walletName: "EVM Aztec Wallet",
  version: "1.0.0",
};

export const AZTEC_DOMAIN_V2 = {
  name: "Aztec",
  version: "1",
  chainId: 31337n,
  verifyingContract: DEFAULT_VERIFYING_CONTRACT_V2,
} as const;

// =============================================================================
// Fixed Type Hashes (pre-computed, match Noir constants)
// =============================================================================

/** keccak256("AccountData(bytes32 address,string walletName,string version)") */
export const ACCOUNT_DATA_TYPE_HASH = keccak256(
  encodePacked(
    ["string"],
    ["AccountData(bytes32 address,string walletName,string version)"],
  ),
);

/** keccak256("TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)") */
export const TX_METADATA_TYPE_HASH = keccak256(
  encodePacked(
    ["string"],
    ["TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)"],
  ),
);

/** keccak256("AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)") */
export const AUTHWIT_APP_DOMAIN_TYPE_HASH = keccak256(
  encodePacked(
    ["string"],
    ["AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)"],
  ),
);

/** keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)") */
export const EIP712_DOMAIN_TYPE_HASH = keccak256(
  encodePacked(
    ["string"],
    [
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ],
  ),
);

// =============================================================================
// Referenced type strings (fixed, for building encode_type)
// =============================================================================

const ACCOUNT_DATA_DEF =
  "AccountData(bytes32 address,string walletName,string version)";
const TX_METADATA_DEF =
  "TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)";
const AUTHWIT_APP_DOMAIN_DEF =
  "AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)";

// =============================================================================
// EIP-712 V2 Encoder Class
// =============================================================================

export class Eip712EncoderV2 {
  private chainId: bigint;

  constructor(options?: { chainId?: bigint }) {
    this.chainId = options?.chainId ?? 31337n;
  }

  /**
   * Build typed data for V2 per-call-count entrypoint authorization.
   * Each call has its own FunctionCall{N} and Arguments{N} type.
   * No padding — callCount = functionCalls.length.
   */
  buildEntrypointTypedData2(
    functionCalls: FunctionCallV2[],
    perCallArgTypes: ArgumentType[][],
    accountData: AccountData,
    txMetadata: TxMetadata,
    verifyingContract: Hex = DEFAULT_VERIFYING_CONTRACT_V2,
  ) {
    const types = buildEntrypointTypes(perCallArgTypes);

    const buildArgs = (fc: FunctionCallV2, callIdx: number): Record<string, bigint | Hex> => {
      const values: Record<string, bigint | Hex> = {};
      const argTypes = perCallArgTypes[callIdx];
      for (let i = 0; i < argTypes.length; i++) {
        const val = fc.arguments[`argument${i + 1}`] ?? 0n;
        if (argTypes[i] === "bytes32") {
          values[`argument${i + 1}`] = pad(toHex(val), { size: 32 });
        } else {
          values[`argument${i + 1}`] = val;
        }
      }
      return values;
    };

    const message: Record<string, unknown> = {
      accountData: {
        address: accountData.address,
        walletName: accountData.walletName,
        version: accountData.version,
      },
      txMetadata: {
        feePaymentMethod: txMetadata.feePaymentMethod,
        cancellable: txMetadata.cancellable,
        txNonce: txMetadata.txNonce,
      },
    };

    for (let i = 0; i < functionCalls.length; i++) {
      const fc = functionCalls[i];
      message[`functionCall${i + 1}`] = {
        contract: fc.contract,
        functionSignature: fc.functionSignature,
        arguments: buildArgs(fc, i),
        isPublic: fc.isPublic,
        hideMsgSender: fc.hideMsgSender,
        isStatic: fc.isStatic,
      };
    }

    return {
      types,
      primaryType: "EntrypointAuthorization" as const,
      domain: {
        ...AZTEC_DOMAIN_V2,
        chainId: this.chainId,
        verifyingContract,
      },
      message,
    };
  }

  /**
   * Build typed data for V2 authwit (single function call authorization).
   * Uses unnumbered "Arguments" type.
   */
  buildAuthwitTypedData(
    functionCall: FunctionCallV2,
    argTypes: ArgumentType[],
    verifyingContract: Hex,
  ) {
    const types = buildAuthwitTypes(argTypes);

    const argsValues: Record<string, bigint | Hex> = {};
    for (let i = 0; i < argTypes.length; i++) {
      const val = functionCall.arguments[`argument${i + 1}`] ?? 0n;
      if (argTypes[i] === "bytes32") {
        argsValues[`argument${i + 1}`] = pad(toHex(val), { size: 32 });
      } else {
        argsValues[`argument${i + 1}`] = val;
      }
    }

    return {
      types,
      primaryType: "FunctionCallAuthorization" as const,
      domain: {
        ...AZTEC_DOMAIN_V2,
        chainId: this.chainId,
        verifyingContract,
      },
      message: {
        appDomain: {
          chainId: this.chainId,
          verifyingContract: pad(verifyingContract, { size: 32 }),
        },
        contract: functionCall.contract,
        functionSignature: functionCall.functionSignature,
        arguments: argsValues,
        isPublic: functionCall.isPublic,
      },
    };
  }

  // ===========================================================================
  // Manual hash computation (matches Noir contract)
  // ===========================================================================

  /**
   * Compute hashStruct(AccountData)
   */
  static hashAccountData(accountData: AccountData): Hex {
    const walletNameHash = keccak256(
      encodePacked(["string"], [accountData.walletName]),
    );
    const versionHash = keccak256(
      encodePacked(["string"], [accountData.version]),
    );

    return keccak256(
      concat([
        ACCOUNT_DATA_TYPE_HASH,
        accountData.address,
        walletNameHash,
        versionHash,
      ]),
    );
  }

  /**
   * Compute hashStruct(TxMetadata)
   */
  static hashTxMetadata(txMetadata: TxMetadata): Hex {
    return keccak256(
      concat([
        TX_METADATA_TYPE_HASH,
        pad(toHex(txMetadata.feePaymentMethod), { size: 32 }),
        pad(toHex(txMetadata.cancellable ? 1n : 0n), { size: 32 }),
        pad(toHex(txMetadata.txNonce), { size: 32 }),
      ]),
    );
  }

  /**
   * Compute hashStruct(AuthwitAppDomain)
   */
  static hashAuthwitAppDomain(
    chainId: bigint,
    verifyingContract: Hex,
  ): Hex {
    return keccak256(
      concat([
        AUTHWIT_APP_DOMAIN_TYPE_HASH,
        pad(toHex(chainId), { size: 32 }),
        pad(verifyingContract, { size: 32 }),
      ]),
    );
  }

  /**
   * Compute type_hash for an Arguments struct.
   * E.g. keccak256("Arguments1(bytes32 argument1,uint256 argument2)")
   */
  static computeArgumentsTypeHash(
    structName: string,
    argTypes: ArgumentType[],
  ): Hex {
    const typeString = buildArgumentsTypeString(structName, argTypes);
    return keccak256(encodePacked(["string"], [typeString]));
  }

  /**
   * Compute hashStruct(Arguments{N}) with variable types.
   * Each argument is encoded as its native 32-byte EIP-712 representation.
   */
  static hashArguments(
    structName: string,
    argTypes: ArgumentType[],
    argValues: bigint[],
  ): Hex {
    const typeHash = Eip712EncoderV2.computeArgumentsTypeHash(
      structName,
      argTypes,
    );

    if (argTypes.length === 0) {
      return keccak256(typeHash);
    }

    const encodedArgs = argValues.map((v) => pad(toHex(v), { size: 32 }));
    return keccak256(concat([typeHash, ...encodedArgs]));
  }

  /**
   * Build the full encode_type string for a FunctionCall{N}.
   * encode_type = fcPrimary + argsTypeString
   */
  static buildFunctionCallEncodeType(fcPrimary: string, argsTypeString: string): string {
    return fcPrimary + argsTypeString;
  }

  /**
   * Compute type_hash for a FunctionCall{N} with a specific Arguments{N} definition.
   */
  static computeFunctionCallTypeHash(fcPrimary: string, argsTypeString: string): Hex {
    const encodeType =
      Eip712EncoderV2.buildFunctionCallEncodeType(fcPrimary, argsTypeString);
    return keccak256(encodePacked(["string"], [encodeType]));
  }

  /**
   * Compute hashStruct(FunctionCall{N}) for the V2 struct layout.
   */
  static hashFunctionCallV2(
    fcPrimary: string,
    argsStructName: string,
    contract: Hex,
    functionSignature: string,
    argTypes: ArgumentType[],
    argValues: bigint[],
    isPublic: boolean,
    hideMsgSender: boolean,
    isStatic: boolean,
  ): Hex {
    const argsTypeString = buildArgumentsTypeString(argsStructName, argTypes);
    const typeHash =
      Eip712EncoderV2.computeFunctionCallTypeHash(fcPrimary, argsTypeString);

    const sigHash = keccak256(
      encodePacked(["string"], [functionSignature]),
    );
    const argsHash = Eip712EncoderV2.hashArguments(
      argsStructName,
      argTypes,
      argValues,
    );

    return keccak256(
      concat([
        typeHash,
        contract,
        sigHash,
        argsHash,
        pad(toHex(isPublic ? 1n : 0n), { size: 32 }),
        pad(toHex(hideMsgSender ? 1n : 0n), { size: 32 }),
        pad(toHex(isStatic ? 1n : 0n), { size: 32 }),
      ]),
    );
  }

  /**
   * Build the full encode_type string for EntrypointAuthorization.
   * Referenced types are in alphabetical order per EIP-712 spec:
   * primary + AccountData + Arguments1..N + FunctionCall1..N + TxMetadata
   */
  static buildEntrypointEncodeType(...argsTypeStrings: string[]): string {
    const callCount = argsTypeStrings.length;
    const authPrimary = buildEntrypointAuthPrimary(callCount);
    let result = authPrimary + ACCOUNT_DATA_DEF;
    for (const ts of argsTypeStrings) {
      result += ts;
    }
    for (let i = 1; i <= callCount; i++) {
      result += FC_PRIMARIES[i];
    }
    result += TX_METADATA_DEF;
    return result;
  }

  /**
   * Compute type_hash for EntrypointAuthorization with per-slot Arguments definitions.
   */
  static computeEntrypointTypeHash(perCallArgTypes: ArgumentType[][]): Hex {
    const argsTypeStrings = perCallArgTypes.map(
      (argTypes, i) => buildArgumentsTypeString(`Arguments${i + 1}`, argTypes),
    );
    const encodeType =
      Eip712EncoderV2.buildEntrypointEncodeType(...argsTypeStrings);
    return keccak256(encodePacked(["string"], [encodeType]));
  }

  /**
   * Compute hashStruct(EntrypointAuthorization).
   */
  static hashEntrypointAuthorization(
    accountDataHash: Hex,
    fcHashes: Hex[],
    txMetadataHash: Hex,
    perCallArgTypes: ArgumentType[][],
  ): Hex {
    const typeHash = Eip712EncoderV2.computeEntrypointTypeHash(perCallArgTypes);

    return keccak256(
      concat([
        typeHash,
        accountDataHash,
        ...fcHashes,
        txMetadataHash,
      ]),
    );
  }

  /**
   * Build the full encode_type string for FunctionCallAuthorization (authwit).
   */
  static buildAuthwitEncodeType(argsTypeString: string): string {
    // Referenced types in alphabetical order:
    // Arguments, AuthwitAppDomain
    return FC_AUTH_PRIMARY + argsTypeString + AUTHWIT_APP_DOMAIN_DEF;
  }

  /**
   * Compute type_hash for FunctionCallAuthorization.
   */
  static computeAuthwitTypeHash(argTypes: ArgumentType[]): Hex {
    const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
    const encodeType = Eip712EncoderV2.buildAuthwitEncodeType(argsTypeString);
    return keccak256(encodePacked(["string"], [encodeType]));
  }

  /**
   * Compute hashStruct(FunctionCallAuthorization) for authwit.
   */
  static hashFunctionCallAuthorization(
    authwitDomainHash: Hex,
    contract: Hex,
    functionSignature: string,
    argTypes: ArgumentType[],
    argValues: bigint[],
    isPublic: boolean,
  ): Hex {
    const typeHash = Eip712EncoderV2.computeAuthwitTypeHash(argTypes);
    const sigHash = keccak256(
      encodePacked(["string"], [functionSignature]),
    );
    const argsHash = Eip712EncoderV2.hashArguments(
      "Arguments",
      argTypes,
      argValues,
    );

    return keccak256(
      concat([
        typeHash,
        authwitDomainHash,
        contract,
        sigHash,
        argsHash,
        pad(toHex(isPublic ? 1n : 0n), { size: 32 }),
      ]),
    );
  }

  /**
   * Compute domain separator with verifyingContract
   */
  static computeDomainSeparator(
    chainId: bigint,
    verifyingContract: Hex,
  ): Hex {
    return keccak256(
      concat([
        EIP712_DOMAIN_TYPE_HASH,
        keccak256(encodePacked(["string"], [AZTEC_DOMAIN_V2.name])),
        keccak256(encodePacked(["string"], [AZTEC_DOMAIN_V2.version])),
        pad(toHex(chainId), { size: 32 }),
        pad(verifyingContract, { size: 32 }),
      ]),
    );
  }

  /**
   * Compute final EIP-712 payload (what gets signed).
   */
  static computeEip712Payload(
    domainSeparator: Hex,
    messageHash: Hex,
  ): Hex {
    return keccak256(concat(["0x1901", domainSeparator, messageHash]));
  }
}
