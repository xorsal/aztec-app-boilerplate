/**
 * Unit tests for EIP-712 V2 Types
 */

import { describe, it, expect } from "vitest";
import {
  ACCOUNT_MAX_CALLS_V2,
  MAX_ARGS_V2,
  MAX_SERIALIZED_ARGS_V2,
  MAX_SIGNATURE_SIZE_V2,
  MAX_ARGS_TYPE_STRING_LEN,
  MERKLE_DEPTH,
  EIP712_WITNESS_V2_2_SLOT,
  EIP712_AUTHWIT_V2_SLOT,
  DEFAULT_VERIFYING_CONTRACT_V2,
  EMPTY_FUNCTION_CALL_V2,
  ENTRYPOINT_AUTH_PRIMARY,
  FC_PRIMARY,
  FC_AUTH_PRIMARY,
  EIP712_TYPES_V2_BASE,
  buildArgumentsTypeDef,
  buildArgumentsTypeString,
  buildEntrypointTypes,
  buildAuthwitTypes,
  type ArgumentType,
} from "../../src/lib/eip712-types-v2.js";

describe("EIP-712 V2 Types", () => {
  describe("constants", () => {
    it("should have ACCOUNT_MAX_CALLS_V2 = 4", () => {
      expect(ACCOUNT_MAX_CALLS_V2).toBe(4);
    });

    it("should have MAX_ARGS_V2 = 10", () => {
      expect(MAX_ARGS_V2).toBe(10);
    });

    it("should have MAX_SERIALIZED_ARGS_V2 = 20", () => {
      expect(MAX_SERIALIZED_ARGS_V2).toBe(20);
    });

    it("should have MAX_SIGNATURE_SIZE_V2 = 128", () => {
      expect(MAX_SIGNATURE_SIZE_V2).toBe(128);
    });

    it("should have MAX_ARGS_TYPE_STRING_LEN = 256", () => {
      expect(MAX_ARGS_TYPE_STRING_LEN).toBe(256);
    });

    it("should have MERKLE_DEPTH = 17", () => {
      expect(MERKLE_DEPTH).toBe(17);
    });

    it("should have valid capsule slots", () => {
      expect(typeof EIP712_WITNESS_V2_2_SLOT).toBe("bigint");
      expect(typeof EIP712_AUTHWIT_V2_SLOT).toBe("bigint");
      expect(EIP712_WITNESS_V2_2_SLOT).not.toBe(EIP712_AUTHWIT_V2_SLOT);
    });

    it("should have valid default verifying contract", () => {
      expect(DEFAULT_VERIFYING_CONTRACT_V2).toMatch(/^0x[0-9a-f]{40}$/i);
    });
  });

  describe("EMPTY_FUNCTION_CALL_V2", () => {
    it("should have zero address contract", () => {
      expect(EMPTY_FUNCTION_CALL_V2.contract).toBe(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      );
    });

    it("should have empty function signature", () => {
      expect(EMPTY_FUNCTION_CALL_V2.functionSignature).toBe("");
    });

    it("should have empty arguments object", () => {
      expect(EMPTY_FUNCTION_CALL_V2.arguments).toEqual({});
    });

    it("should have boolean flags set to false", () => {
      expect(EMPTY_FUNCTION_CALL_V2.isPublic).toBe(false);
      expect(EMPTY_FUNCTION_CALL_V2.hideMsgSender).toBe(false);
      expect(EMPTY_FUNCTION_CALL_V2.isStatic).toBe(false);
    });
  });

  describe("buildArgumentsTypeDef", () => {
    it("should return empty array for 0 args", () => {
      const result = buildArgumentsTypeDef([]);
      expect(result).toEqual([]);
    });

    it("should return single argument type def for 1 arg", () => {
      const result = buildArgumentsTypeDef(["bytes32"]);
      expect(result).toEqual([{ name: "argument1", type: "bytes32" }]);
    });

    it("should handle 5 mixed argument types", () => {
      const types: ArgumentType[] = [
        "bytes32",
        "uint256",
        "int256",
        "bytes32",
        "uint256",
      ];
      const result = buildArgumentsTypeDef(types);
      expect(result).toHaveLength(5);
      expect(result[0]).toEqual({ name: "argument1", type: "bytes32" });
      expect(result[1]).toEqual({ name: "argument2", type: "uint256" });
      expect(result[2]).toEqual({ name: "argument3", type: "int256" });
      expect(result[3]).toEqual({ name: "argument4", type: "bytes32" });
      expect(result[4]).toEqual({ name: "argument5", type: "uint256" });
    });

    it("should handle max 10 argument types", () => {
      const types: ArgumentType[] = Array(10).fill("uint256");
      const result = buildArgumentsTypeDef(types);
      expect(result).toHaveLength(10);
      for (let i = 0; i < 10; i++) {
        expect(result[i].name).toBe(`argument${i + 1}`);
        expect(result[i].type).toBe("uint256");
      }
    });
  });

  describe("buildArgumentsTypeString", () => {
    it("should produce empty-args string for 0 args", () => {
      const result = buildArgumentsTypeString("Arguments1", []);
      expect(result).toBe("Arguments1()");
    });

    it("should produce correct string for 1 arg", () => {
      const result = buildArgumentsTypeString("Arguments", ["bytes32"]);
      expect(result).toBe("Arguments(bytes32 argument1)");
    });

    it("should produce correct string for multiple args", () => {
      const result = buildArgumentsTypeString("Arguments2", [
        "bytes32",
        "uint256",
        "int256",
      ]);
      expect(result).toBe(
        "Arguments2(bytes32 argument1,uint256 argument2,int256 argument3)",
      );
    });

    it("should use correct struct name", () => {
      const result = buildArgumentsTypeString("Arguments1", ["uint256"]);
      expect(result.startsWith("Arguments1(")).toBe(true);
    });
  });

  describe("buildEntrypointTypes", () => {
    it("should include all base types", () => {
      const types = buildEntrypointTypes(["bytes32"]);
      expect(types.EIP712Domain).toBeDefined();
      expect(types.AccountData).toBeDefined();
      expect(types.TxMetadata).toBeDefined();
      expect(types.EntrypointAuthorization).toBeDefined();
      expect(types.FunctionCall).toBeDefined();
      expect(types.AuthwitAppDomain).toBeDefined();
      expect(types.FunctionCallAuthorization).toBeDefined();
    });

    it("should include dynamic Arguments type", () => {
      const types = buildEntrypointTypes(["bytes32", "uint256"]);
      expect(types.Arguments).toEqual([
        { name: "argument1", type: "bytes32" },
        { name: "argument2", type: "uint256" },
      ]);
    });

    it("should handle empty argument types", () => {
      const types = buildEntrypointTypes([]);
      expect(types.Arguments).toEqual([]);
    });
  });

  describe("buildAuthwitTypes", () => {
    it("should include all base types plus Arguments", () => {
      const types = buildAuthwitTypes(["bytes32"]);
      expect(types.EIP712Domain).toBeDefined();
      expect(types.AuthwitAppDomain).toBeDefined();
      expect(types.FunctionCallAuthorization).toBeDefined();
      expect(types.Arguments).toBeDefined();
    });

    it("should build correct Arguments type definition", () => {
      const types = buildAuthwitTypes(["bytes32", "uint256", "int256"]);
      expect(types.Arguments).toEqual([
        { name: "argument1", type: "bytes32" },
        { name: "argument2", type: "uint256" },
        { name: "argument3", type: "int256" },
      ]);
    });

    it("should handle empty argument types", () => {
      const types = buildAuthwitTypes([]);
      expect(types.Arguments).toEqual([]);
    });
  });

  describe("primary struct strings", () => {
    it("should have correct EntrypointAuthorization primary", () => {
      expect(ENTRYPOINT_AUTH_PRIMARY).toBe(
        "EntrypointAuthorization(AccountData accountData,FunctionCall functionCall1,FunctionCall functionCall2,FunctionCall functionCall3,FunctionCall functionCall4,TxMetadata txMetadata)",
      );
    });

    it("should have correct FunctionCall primary", () => {
      expect(FC_PRIMARY).toBe(
        "FunctionCall(bytes32 contract,string functionSignature,Arguments arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
      );
    });

    it("should have correct FunctionCallAuthorization primary", () => {
      expect(FC_AUTH_PRIMARY).toBe(
        "FunctionCallAuthorization(AuthwitAppDomain appDomain,bytes32 contract,string functionSignature,Arguments arguments,bool isPublic)",
      );
    });
  });

  describe("EIP712_TYPES_V2_BASE", () => {
    it("should have EIP712Domain type with correct fields", () => {
      expect(EIP712_TYPES_V2_BASE.EIP712Domain).toContainEqual({
        name: "name",
        type: "string",
      });
      expect(EIP712_TYPES_V2_BASE.EIP712Domain).toContainEqual({
        name: "version",
        type: "string",
      });
      expect(EIP712_TYPES_V2_BASE.EIP712Domain).toContainEqual({
        name: "chainId",
        type: "uint256",
      });
      expect(EIP712_TYPES_V2_BASE.EIP712Domain).toContainEqual({
        name: "verifyingContract",
        type: "address",
      });
    });

    it("should have AccountData type with correct fields", () => {
      expect(EIP712_TYPES_V2_BASE.AccountData).toContainEqual({
        name: "address",
        type: "bytes32",
      });
      expect(EIP712_TYPES_V2_BASE.AccountData).toContainEqual({
        name: "walletName",
        type: "string",
      });
      expect(EIP712_TYPES_V2_BASE.AccountData).toContainEqual({
        name: "version",
        type: "string",
      });
    });

    it("should have TxMetadata type with correct fields", () => {
      expect(EIP712_TYPES_V2_BASE.TxMetadata).toContainEqual({
        name: "feePaymentMethod",
        type: "uint8",
      });
      expect(EIP712_TYPES_V2_BASE.TxMetadata).toContainEqual({
        name: "cancellable",
        type: "bool",
      });
      expect(EIP712_TYPES_V2_BASE.TxMetadata).toContainEqual({
        name: "txNonce",
        type: "uint256",
      });
    });

    it("should have FunctionCall referencing Arguments", () => {
      expect(EIP712_TYPES_V2_BASE.FunctionCall).toContainEqual({
        name: "arguments",
        type: "Arguments",
      });
    });

    it("should have FunctionCallAuthorization referencing Arguments", () => {
      expect(EIP712_TYPES_V2_BASE.FunctionCallAuthorization).toContainEqual({
        name: "arguments",
        type: "Arguments",
      });
    });
  });
});
