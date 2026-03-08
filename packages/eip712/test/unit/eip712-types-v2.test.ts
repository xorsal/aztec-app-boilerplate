/**
 * Unit tests for EIP-712 V2 Types
 */

import { describe, it, expect } from "vitest";
import {
  MAX_ENTRYPOINT_CALLS,
  MAX_ARGS_V2,
  MAX_SERIALIZED_ARGS_V2,
  MAX_SIGNATURE_SIZE_V2,
  MAX_ARGS_TYPE_STRING_LEN,
  MERKLE_DEPTH,
  EIP712_WITNESS_V2_SLOTS,
  EIP712_AUTHWIT_V2_SLOT,
  DEFAULT_VERIFYING_CONTRACT_V2,
  FC_PRIMARIES,
  FC_AUTH_PRIMARY,
  buildEntrypointAuthPrimary,
  EIP712_TYPES_V2_BASE,
  buildArgumentsTypeDef,
  buildArgumentsTypeString,
  buildEntrypointTypes,
  buildAuthwitTypes,
  type ArgumentType,
} from "../../src/lib/eip712-types-v2.js";

describe("EIP-712 V2 Types", () => {
  describe("constants", () => {
    it("should have MAX_ENTRYPOINT_CALLS = 4", () => {
      expect(MAX_ENTRYPOINT_CALLS).toBe(4);
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

    it("should have valid EIP712_WITNESS_V2_SLOTS for keys 1-4", () => {
      for (let i = 1; i <= 4; i++) {
        expect(typeof EIP712_WITNESS_V2_SLOTS[i]).toBe("bigint");
      }
    });

    it("should have all unique capsule slots", () => {
      const witnessSlots = Object.values(EIP712_WITNESS_V2_SLOTS);
      const allSlots = [...witnessSlots, EIP712_AUTHWIT_V2_SLOT];
      const uniqueSlots = new Set(allSlots);
      expect(uniqueSlots.size).toBe(allSlots.length);
    });

    it("should have valid default verifying contract", () => {
      expect(DEFAULT_VERIFYING_CONTRACT_V2).toMatch(/^0x[0-9a-f]{40}$/i);
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
    it("should include base types and per-slot FunctionCall/Arguments for 1 call", () => {
      const types = buildEntrypointTypes([["bytes32"]]);
      expect(types.EIP712Domain).toBeDefined();
      expect(types.AccountData).toBeDefined();
      expect(types.TxMetadata).toBeDefined();
      expect(types.EntrypointAuthorization).toBeDefined();
      expect(types.AuthwitAppDomain).toBeDefined();
      expect(types.FunctionCallAuthorization).toBeDefined();
      expect(types.FunctionCall1).toBeDefined();
      expect(types.Arguments1).toBeDefined();
    });

    it("should not include unified FunctionCall type", () => {
      const types = buildEntrypointTypes([["bytes32"]]);
      expect(types.FunctionCall).toBeUndefined();
      expect(types.Arguments).toBeUndefined();
    });

    it("should include dynamic per-slot Arguments types", () => {
      const types = buildEntrypointTypes([["bytes32", "uint256"]]);
      expect(types.Arguments1).toEqual([
        { name: "argument1", type: "bytes32" },
        { name: "argument2", type: "uint256" },
      ]);
    });

    it("should handle 2 calls with different arg types", () => {
      const types = buildEntrypointTypes([
        ["bytes32", "uint256"],
        ["int256"],
      ]);
      expect(types.FunctionCall1).toBeDefined();
      expect(types.FunctionCall2).toBeDefined();
      expect(types.Arguments1).toEqual([
        { name: "argument1", type: "bytes32" },
        { name: "argument2", type: "uint256" },
      ]);
      expect(types.Arguments2).toEqual([
        { name: "argument1", type: "int256" },
      ]);
    });

    it("should build EntrypointAuthorization with per-slot FunctionCall references", () => {
      const types = buildEntrypointTypes([
        ["bytes32", "uint256"],
        ["int256"],
      ]);
      expect(types.EntrypointAuthorization).toContainEqual({
        name: "functionCall1",
        type: "FunctionCall1",
      });
      expect(types.EntrypointAuthorization).toContainEqual({
        name: "functionCall2",
        type: "FunctionCall2",
      });
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
    it("should have correct buildEntrypointAuthPrimary for 1 call", () => {
      expect(buildEntrypointAuthPrimary(1)).toBe(
        "EntrypointAuthorization(AccountData accountData,FunctionCall1 functionCall1,TxMetadata txMetadata)",
      );
    });

    it("should have correct buildEntrypointAuthPrimary for 2 calls", () => {
      expect(buildEntrypointAuthPrimary(2)).toBe(
        "EntrypointAuthorization(AccountData accountData,FunctionCall1 functionCall1,FunctionCall2 functionCall2,TxMetadata txMetadata)",
      );
    });

    it("should have correct buildEntrypointAuthPrimary for 3 calls", () => {
      expect(buildEntrypointAuthPrimary(3)).toBe(
        "EntrypointAuthorization(AccountData accountData,FunctionCall1 functionCall1,FunctionCall2 functionCall2,FunctionCall3 functionCall3,TxMetadata txMetadata)",
      );
    });

    it("should have correct buildEntrypointAuthPrimary for 4 calls", () => {
      expect(buildEntrypointAuthPrimary(4)).toBe(
        "EntrypointAuthorization(AccountData accountData,FunctionCall1 functionCall1,FunctionCall2 functionCall2,FunctionCall3 functionCall3,FunctionCall4 functionCall4,TxMetadata txMetadata)",
      );
    });

    it("should have correct FC_PRIMARIES for slot 1", () => {
      expect(FC_PRIMARIES[1]).toBe(
        "FunctionCall1(bytes32 contract,string functionSignature,Arguments1 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
      );
    });

    it("should have correct FC_PRIMARIES for slot 2", () => {
      expect(FC_PRIMARIES[2]).toBe(
        "FunctionCall2(bytes32 contract,string functionSignature,Arguments2 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
      );
    });

    it("should have correct FC_PRIMARIES for slot 3", () => {
      expect(FC_PRIMARIES[3]).toBe(
        "FunctionCall3(bytes32 contract,string functionSignature,Arguments3 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
      );
    });

    it("should have correct FC_PRIMARIES for slot 4", () => {
      expect(FC_PRIMARIES[4]).toBe(
        "FunctionCall4(bytes32 contract,string functionSignature,Arguments4 arguments,bool isPublic,bool hideMsgSender,bool isStatic)",
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

    it("should have FunctionCallAuthorization referencing Arguments", () => {
      expect(EIP712_TYPES_V2_BASE.FunctionCallAuthorization).toContainEqual({
        name: "arguments",
        type: "Arguments",
      });
    });
  });
});
