/**
 * Unit tests for EIP-712 V2 Encoder
 */

import { describe, it, expect } from "vitest";
import { keccak256, encodePacked, pad, toHex } from "viem";
import {
  Eip712EncoderV2,
  DEFAULT_ACCOUNT_DATA,
  AZTEC_DOMAIN_V2,
  ACCOUNT_DATA_TYPE_HASH,
  TX_METADATA_TYPE_HASH,
  AUTHWIT_APP_DOMAIN_TYPE_HASH,
  EIP712_DOMAIN_TYPE_HASH,
} from "../../src/lib/eip712-encoder-v2.js";
import {
  EMPTY_FUNCTION_CALL_V2,
  ENTRYPOINT_AUTH_PRIMARY,
  FC_PRIMARY,
  FC_AUTH_PRIMARY,
  DEFAULT_VERIFYING_CONTRACT_V2,
  buildArgumentsTypeString,
  type ArgumentType,
  type FunctionCallV2,
  type AccountData,
  type TxMetadata,
} from "../../src/lib/eip712-types-v2.js";

describe("Eip712EncoderV2", () => {
  describe("constructor", () => {
    it("should use default chain ID 31337", () => {
      const encoder = new Eip712EncoderV2();
      const typedData = encoder.buildEntrypointTypedData2(
        [],
        [],
        DEFAULT_ACCOUNT_DATA,
        { feePaymentMethod: 0, cancellable: false, txNonce: 0n },
      );
      expect(typedData.domain.chainId).toBe(31337n);
    });

    it("should accept custom chain ID", () => {
      const encoder = new Eip712EncoderV2({ chainId: 1n });
      const typedData = encoder.buildEntrypointTypedData2(
        [],
        [],
        DEFAULT_ACCOUNT_DATA,
        { feePaymentMethod: 0, cancellable: false, txNonce: 0n },
      );
      expect(typedData.domain.chainId).toBe(1n);
    });
  });

  describe("buildEntrypointTypedData2", () => {
    it("should produce valid typed data structure", () => {
      const encoder = new Eip712EncoderV2();
      const fc: FunctionCallV2 = {
        contract:
          "0x0000000000000000000000000000000000000000000000000000000000000001",
        functionSignature: "transfer(Field,u128)",
        arguments: { argument1: 100n, argument2: 200n },
        isPublic: false,
        hideMsgSender: false,
        isStatic: false,
      };
      const typedData = encoder.buildEntrypointTypedData2(
        [fc],
        ["bytes32", "uint256"],
        DEFAULT_ACCOUNT_DATA,
        { feePaymentMethod: 0, cancellable: false, txNonce: 42n },
      );

      expect(typedData.primaryType).toBe("EntrypointAuthorization");
      expect(typedData.types.EIP712Domain).toBeDefined();
      expect(typedData.types.Arguments).toBeDefined();
      expect(typedData.message.accountData).toBeDefined();
      expect(typedData.message.functionCall1).toBeDefined();
      expect(typedData.message.functionCall2).toBeDefined();
      expect(typedData.message.functionCall3).toBeDefined();
      expect(typedData.message.functionCall4).toBeDefined();
      expect(typedData.message.txMetadata).toBeDefined();
    });

    it("should include correct argument values in message", () => {
      const encoder = new Eip712EncoderV2();
      const fc: FunctionCallV2 = {
        contract:
          "0x0000000000000000000000000000000000000000000000000000000000000001",
        functionSignature: "test(Field)",
        arguments: { argument1: 42n },
        isPublic: false,
        hideMsgSender: false,
        isStatic: false,
      };
      const typedData = encoder.buildEntrypointTypedData2(
        [fc],
        ["uint256"],
        DEFAULT_ACCOUNT_DATA,
        { feePaymentMethod: 0, cancellable: false, txNonce: 0n },
      );

      expect(typedData.message.functionCall1.arguments).toEqual({
        argument1: 42n,
      });
    });

    it("should use provided verifying contract", () => {
      const encoder = new Eip712EncoderV2();
      const customContract =
        "0xdeadbeef00000000000000000000000000000000" as const;
      const typedData = encoder.buildEntrypointTypedData2(
        [],
        [],
        DEFAULT_ACCOUNT_DATA,
        { feePaymentMethod: 0, cancellable: false, txNonce: 0n },
        customContract,
      );

      expect(typedData.domain.verifyingContract).toBe(customContract);
    });

    it("should include tx metadata in message", () => {
      const encoder = new Eip712EncoderV2();
      const typedData = encoder.buildEntrypointTypedData2(
        [],
        [],
        DEFAULT_ACCOUNT_DATA,
        { feePaymentMethod: 1, cancellable: true, txNonce: 99n },
      );

      expect(typedData.message.txMetadata.feePaymentMethod).toBe(1);
      expect(typedData.message.txMetadata.cancellable).toBe(true);
      expect(typedData.message.txMetadata.txNonce).toBe(99n);
    });
  });

  describe("buildAuthwitTypedData", () => {
    it("should produce valid authwit typed data", () => {
      const encoder = new Eip712EncoderV2();
      const fc: FunctionCallV2 = {
        contract:
          "0x0000000000000000000000000000000000000000000000000000000000000001",
        functionSignature: "transfer_from(Field,Field,u128)",
        arguments: { argument1: 1n, argument2: 2n, argument3: 100n },
        isPublic: false,
        hideMsgSender: false,
        isStatic: false,
      };
      const verifyingContract =
        "0x1234567890123456789012345678901234567890" as const;
      const typedData = encoder.buildAuthwitTypedData(
        fc,
        ["bytes32", "bytes32", "uint256"],
        verifyingContract,
      );

      expect(typedData.primaryType).toBe("FunctionCallAuthorization");
      expect(typedData.types.Arguments).toBeDefined();
      expect(typedData.message.functionSignature).toBe(
        "transfer_from(Field,Field,u128)",
      );
      expect(typedData.domain.verifyingContract).toBe(verifyingContract);
    });

    it("should include appDomain in message", () => {
      const encoder = new Eip712EncoderV2({ chainId: 42n });
      const fc: FunctionCallV2 = {
        contract:
          "0x0000000000000000000000000000000000000000000000000000000000000001",
        functionSignature: "test()",
        arguments: {},
        isPublic: false,
        hideMsgSender: false,
        isStatic: false,
      };
      const verifyingContract =
        "0x0000000000000000000000000000000000000001" as const;
      const typedData = encoder.buildAuthwitTypedData(
        fc,
        [],
        verifyingContract,
      );

      expect(typedData.message.appDomain.chainId).toBe(42n);
    });
  });

  describe("static hash methods", () => {
    it("hashAccountData should produce keccak256 hash", () => {
      const hash = Eip712EncoderV2.hashAccountData(DEFAULT_ACCOUNT_DATA);
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("hashAccountData should be deterministic", () => {
      const hash1 = Eip712EncoderV2.hashAccountData(DEFAULT_ACCOUNT_DATA);
      const hash2 = Eip712EncoderV2.hashAccountData(DEFAULT_ACCOUNT_DATA);
      expect(hash1).toBe(hash2);
    });

    it("hashAccountData should differ for different inputs", () => {
      const customData: AccountData = {
        address:
          "0x0000000000000000000000000000000000000000000000000000000000000001",
        walletName: "Different Wallet",
        version: "2.0.0",
      };
      const hash1 = Eip712EncoderV2.hashAccountData(DEFAULT_ACCOUNT_DATA);
      const hash2 = Eip712EncoderV2.hashAccountData(customData);
      expect(hash1).not.toBe(hash2);
    });

    it("hashTxMetadata should produce keccak256 hash", () => {
      const hash = Eip712EncoderV2.hashTxMetadata({
        feePaymentMethod: 0,
        cancellable: false,
        txNonce: 0n,
      });
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("hashTxMetadata should differ for different nonces", () => {
      const hash1 = Eip712EncoderV2.hashTxMetadata({
        feePaymentMethod: 0,
        cancellable: false,
        txNonce: 1n,
      });
      const hash2 = Eip712EncoderV2.hashTxMetadata({
        feePaymentMethod: 0,
        cancellable: false,
        txNonce: 2n,
      });
      expect(hash1).not.toBe(hash2);
    });

    it("hashAuthwitAppDomain should produce keccak256 hash", () => {
      const hash = Eip712EncoderV2.hashAuthwitAppDomain(
        31337n,
        "0x0000000000000000000000000000000000000000000000000000000000000001",
      );
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("computeArgumentsTypeHash", () => {
    it("should match manual keccak256 computation for empty args", () => {
      const typeString = buildArgumentsTypeString("Arguments1", []);
      const expectedHash = keccak256(
        encodePacked(["string"], [typeString]),
      );
      const actual = Eip712EncoderV2.computeArgumentsTypeHash(
        "Arguments1",
        [],
      );
      expect(actual).toBe(expectedHash);
    });

    it("should match manual keccak256 computation for single arg", () => {
      const typeString = buildArgumentsTypeString("Arguments", ["bytes32"]);
      const expectedHash = keccak256(
        encodePacked(["string"], [typeString]),
      );
      const actual = Eip712EncoderV2.computeArgumentsTypeHash("Arguments", [
        "bytes32",
      ]);
      expect(actual).toBe(expectedHash);
    });

    it("should match manual keccak256 computation for mixed args", () => {
      const argTypes: ArgumentType[] = [
        "bytes32",
        "uint256",
        "int256",
        "bytes32",
      ];
      const typeString = buildArgumentsTypeString("Arguments2", argTypes);
      const expectedHash = keccak256(
        encodePacked(["string"], [typeString]),
      );
      const actual = Eip712EncoderV2.computeArgumentsTypeHash(
        "Arguments2",
        argTypes,
      );
      expect(actual).toBe(expectedHash);
    });

    it("should produce different hashes for different arg types", () => {
      const hash1 = Eip712EncoderV2.computeArgumentsTypeHash("Arguments", [
        "bytes32",
      ]);
      const hash2 = Eip712EncoderV2.computeArgumentsTypeHash("Arguments", [
        "uint256",
      ]);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("buildEntrypointEncodeType", () => {
    it("should produce correctly ordered type string", () => {
      const argsTypeString = buildArgumentsTypeString("Arguments", [
        "bytes32",
      ]);
      const encodeType = Eip712EncoderV2.buildEntrypointEncodeType(
        argsTypeString,
      );

      // Should start with primary
      expect(encodeType).toContain(ENTRYPOINT_AUTH_PRIMARY);
      // Should contain referenced types
      expect(encodeType).toContain(
        "AccountData(bytes32 address,string walletName,string version)",
      );
      expect(encodeType).toContain(argsTypeString);
      expect(encodeType).toContain(FC_PRIMARY);
      expect(encodeType).toContain(
        "TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)",
      );
    });

    it("should have primary type first, then referenced types in alphabetical order", () => {
      const argsTypeString = buildArgumentsTypeString("Arguments", [
        "bytes32",
      ]);
      const encodeType = Eip712EncoderV2.buildEntrypointEncodeType(
        argsTypeString,
      );

      // Check that AccountData comes before Arguments which comes before FunctionCall
      const accountDataIdx = encodeType.indexOf("AccountData(");
      const argsIdx = encodeType.indexOf("Arguments(");
      const fcIdx = encodeType.indexOf("FunctionCall(");
      const txMetaIdx = encodeType.indexOf("TxMetadata(");

      expect(accountDataIdx).toBeLessThan(argsIdx);
      expect(argsIdx).toBeLessThan(fcIdx);
      expect(fcIdx).toBeLessThan(txMetaIdx);
    });
  });

  describe("domain separator", () => {
    it("should compute valid domain separator", () => {
      const separator = Eip712EncoderV2.computeDomainSeparator(
        31337n,
        DEFAULT_VERIFYING_CONTRACT_V2,
      );
      expect(separator).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("should be deterministic", () => {
      const sep1 = Eip712EncoderV2.computeDomainSeparator(
        31337n,
        DEFAULT_VERIFYING_CONTRACT_V2,
      );
      const sep2 = Eip712EncoderV2.computeDomainSeparator(
        31337n,
        DEFAULT_VERIFYING_CONTRACT_V2,
      );
      expect(sep1).toBe(sep2);
    });

    it("should differ for different chain IDs", () => {
      const sep1 = Eip712EncoderV2.computeDomainSeparator(
        31337n,
        DEFAULT_VERIFYING_CONTRACT_V2,
      );
      const sep2 = Eip712EncoderV2.computeDomainSeparator(
        1n,
        DEFAULT_VERIFYING_CONTRACT_V2,
      );
      expect(sep1).not.toBe(sep2);
    });

    it("should differ for different verifying contracts", () => {
      const sep1 = Eip712EncoderV2.computeDomainSeparator(
        31337n,
        "0x0000000000000000000000000000000000000001",
      );
      const sep2 = Eip712EncoderV2.computeDomainSeparator(
        31337n,
        "0x0000000000000000000000000000000000000002",
      );
      expect(sep1).not.toBe(sep2);
    });
  });

  describe("type hashes", () => {
    it("ACCOUNT_DATA_TYPE_HASH should be valid keccak256", () => {
      expect(ACCOUNT_DATA_TYPE_HASH).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("TX_METADATA_TYPE_HASH should be valid keccak256", () => {
      expect(TX_METADATA_TYPE_HASH).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("AUTHWIT_APP_DOMAIN_TYPE_HASH should be valid keccak256", () => {
      expect(AUTHWIT_APP_DOMAIN_TYPE_HASH).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("EIP712_DOMAIN_TYPE_HASH should be valid keccak256", () => {
      expect(EIP712_DOMAIN_TYPE_HASH).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("ACCOUNT_DATA_TYPE_HASH should match manual computation", () => {
      const expected = keccak256(
        encodePacked(
          ["string"],
          ["AccountData(bytes32 address,string walletName,string version)"],
        ),
      );
      expect(ACCOUNT_DATA_TYPE_HASH).toBe(expected);
    });

    it("TX_METADATA_TYPE_HASH should match manual computation", () => {
      const expected = keccak256(
        encodePacked(
          ["string"],
          [
            "TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)",
          ],
        ),
      );
      expect(TX_METADATA_TYPE_HASH).toBe(expected);
    });
  });
});
