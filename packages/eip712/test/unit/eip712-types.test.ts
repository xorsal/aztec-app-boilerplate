/**
 * Unit tests for EIP-712 Types
 */

import { describe, it, expect } from "vitest";
import {
  ACCOUNT_MAX_CALLS,
  EIP712_TYPES_5,
  EMPTY_FUNCTION_CALL,
  EIP712_WITNESS_5_SLOT,
  EIP712_AUTHWIT_SLOT,
  MAX_SERIALIZED_ARGS,
  MAX_SIGNATURE_SIZE,
  EIP712_WITNESS_5_SERIALIZED_LEN,
  EIP712_AUTHWIT_SERIALIZED_LEN,
  DEFAULT_VERIFYING_CONTRACT,
} from "../../src/lib/eip712-types";

describe("EIP-712 Types", () => {
  describe("constants", () => {
    it("should have ACCOUNT_MAX_CALLS = 5", () => {
      expect(ACCOUNT_MAX_CALLS).toBe(5);
    });

    it("should have MAX_SERIALIZED_ARGS = 20", () => {
      expect(MAX_SERIALIZED_ARGS).toBe(20);
    });

    it("should have MAX_SIGNATURE_SIZE = 128", () => {
      expect(MAX_SIGNATURE_SIZE).toBe(128);
    });

    it("should have valid capsule slots", () => {
      expect(typeof EIP712_WITNESS_5_SLOT).toBe("bigint");
      expect(typeof EIP712_AUTHWIT_SLOT).toBe("bigint");
      expect(EIP712_WITNESS_5_SLOT).not.toBe(EIP712_AUTHWIT_SLOT);
    });

    it("should have correct serialized lengths", () => {
      // 145 fields for 5-call witness (selector NOT included - derived from signature)
      expect(EIP712_WITNESS_5_SERIALIZED_LEN).toBe(145);
      // 34 fields for authwit witness
      expect(EIP712_AUTHWIT_SERIALIZED_LEN).toBe(34);
    });

    it("should have valid default verifying contract", () => {
      expect(DEFAULT_VERIFYING_CONTRACT).toMatch(/^0x[0-9a-f]{40}$/i);
    });
  });

  describe("EMPTY_FUNCTION_CALL", () => {
    it("should have zero address contract", () => {
      expect(EMPTY_FUNCTION_CALL.contract).toBe(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      );
    });

    it("should have empty function signature", () => {
      expect(EMPTY_FUNCTION_CALL.functionSignature).toBe("");
    });

    it("should have empty arguments array", () => {
      expect(EMPTY_FUNCTION_CALL.arguments).toEqual([]);
    });
  });

  describe("EIP712_TYPES_5", () => {
    it("should have EIP712Domain type", () => {
      expect(EIP712_TYPES_5.EIP712Domain).toBeDefined();
      expect(EIP712_TYPES_5.EIP712Domain).toContainEqual({
        name: "name",
        type: "string",
      });
      expect(EIP712_TYPES_5.EIP712Domain).toContainEqual({
        name: "version",
        type: "string",
      });
      expect(EIP712_TYPES_5.EIP712Domain).toContainEqual({
        name: "chainId",
        type: "uint256",
      });
      expect(EIP712_TYPES_5.EIP712Domain).toContainEqual({
        name: "verifyingContract",
        type: "address",
      });
    });

    it("should have AppDomain type", () => {
      expect(EIP712_TYPES_5.AppDomain).toBeDefined();
      expect(EIP712_TYPES_5.AppDomain).toContainEqual({
        name: "name",
        type: "string",
      });
      expect(EIP712_TYPES_5.AppDomain).toContainEqual({
        name: "salt",
        type: "bytes32",
      });
    });

    it("should have FunctionCall type with arguments array", () => {
      expect(EIP712_TYPES_5.FunctionCall).toBeDefined();
      expect(EIP712_TYPES_5.FunctionCall).toContainEqual({
        name: "contract",
        type: "bytes32",
      });
      expect(EIP712_TYPES_5.FunctionCall).toContainEqual({
        name: "functionSignature",
        type: "string",
      });
      expect(EIP712_TYPES_5.FunctionCall).toContainEqual({
        name: "arguments",
        type: "uint256[]",
      });
    });

    it("should have EntrypointAuthorization type with FunctionCall[5]", () => {
      expect(EIP712_TYPES_5.EntrypointAuthorization).toBeDefined();
      expect(EIP712_TYPES_5.EntrypointAuthorization).toContainEqual({
        name: "functionCalls",
        type: "FunctionCall[5]",
      });
      expect(EIP712_TYPES_5.EntrypointAuthorization).toContainEqual({
        name: "txNonce",
        type: "uint256",
      });
    });

    it("should have AuthwitAppDomain type", () => {
      expect(EIP712_TYPES_5.AuthwitAppDomain).toBeDefined();
      expect(EIP712_TYPES_5.AuthwitAppDomain).toContainEqual({
        name: "chainId",
        type: "uint256",
      });
      expect(EIP712_TYPES_5.AuthwitAppDomain).toContainEqual({
        name: "verifyingContract",
        type: "bytes32",
      });
    });

    it("should have FunctionCallAuthorization type", () => {
      expect(EIP712_TYPES_5.FunctionCallAuthorization).toBeDefined();
      expect(EIP712_TYPES_5.FunctionCallAuthorization).toContainEqual({
        name: "appDomain",
        type: "AuthwitAppDomain",
      });
      expect(EIP712_TYPES_5.FunctionCallAuthorization).toContainEqual({
        name: "functionCall",
        type: "FunctionCall",
      });
    });
  });

  describe("serialized length calculations", () => {
    it("should match expected witness 5 serialized length", () => {
      // Breakdown:
      // - Signature: 3 fields (31+31+2 bytes packed)
      // - Per call (5 calls):
      //   - Function signature: 5 fields (31+31+31+31+4 bytes packed)
      //   - Signature length: 1 field
      //   - Function args: 20 fields
      //   - Args length: 1 field
      //   - Target address: 1 field
      //   Total per call: 28 fields (selector NOT included - derived from signature)
      // - Chain ID: 1 field
      // - Salt: 1 field
      // Total: 3 + (5 * 28) + 1 + 1 = 3 + 140 + 2 = 145

      const signatureFields = 3;
      const fieldsPerCall = 5 + 1 + MAX_SERIALIZED_ARGS + 1 + 1; // 28 (selector NOT included)
      const callsFields = ACCOUNT_MAX_CALLS * fieldsPerCall; // 140
      const metadataFields = 2; // chainId + salt

      const expectedTotal = signatureFields + callsFields + metadataFields;
      expect(expectedTotal).toBe(EIP712_WITNESS_5_SERIALIZED_LEN);
    });

    it("should match expected authwit serialized length", () => {
      // Breakdown:
      // - Signature: 3 fields
      // - Function signature: 5 fields
      // - Signature length: 1 field
      // - Function args: 20 fields
      // - Args length: 1 field
      // - Target address: 1 field
      // - Chain ID: 1 field
      // - Verifying contract: 1 field
      // - Inner hash: 1 field
      // Total: 3 + 5 + 1 + 20 + 1 + 1 + 1 + 1 + 1 = 34

      const signatureFields = 3;
      const funcSigFields = 5;
      const otherFields = 1 + MAX_SERIALIZED_ARGS + 1 + 1 + 1 + 1 + 1; // 26

      const expectedTotal = signatureFields + funcSigFields + otherFields;
      expect(expectedTotal).toBe(EIP712_AUTHWIT_SERIALIZED_LEN);
    });
  });
});
