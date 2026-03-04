/**
 * Unit tests for EIP-712 Helper Utilities
 *
 * These tests verify the pure utility functions for EIP-712 encoding.
 * Tests requiring real contract artifacts (buildFunctionSignature, buildFunctionCallInput)
 * are covered in integration tests.
 */

import { describe, it, expect } from "vitest";
import {
  noirTypeToString,
  argsToFields,
} from "../../src/utils/eip712-helpers";

describe("EIP-712 Helpers", () => {
  describe("noirTypeToString", () => {
    it("should convert Field type", () => {
      const param = {
        name: "test",
        type: { kind: "field" as const },
        visibility: "public" as const,
      };
      expect(noirTypeToString(param)).toBe("Field");
    });

    it("should convert unsigned integer types", () => {
      const u64 = {
        name: "test",
        type: {
          kind: "integer" as const,
          sign: "unsigned" as const,
          width: 64,
        },
        visibility: "public" as const,
      };
      const u128 = {
        name: "test",
        type: {
          kind: "integer" as const,
          sign: "unsigned" as const,
          width: 128,
        },
        visibility: "public" as const,
      };
      expect(noirTypeToString(u64)).toBe("u64");
      expect(noirTypeToString(u128)).toBe("u128");
    });

    it("should convert signed integer types", () => {
      const i32 = {
        name: "test",
        type: { kind: "integer" as const, sign: "signed" as const, width: 32 },
        visibility: "public" as const,
      };
      expect(noirTypeToString(i32)).toBe("i32");
    });

    it("should convert struct types to short name", () => {
      const aztecAddress = {
        name: "test",
        type: {
          kind: "struct" as const,
          path: "aztec::protocol_types::address::aztec_address::AztecAddress",
          fields: [],
        },
        visibility: "public" as const,
      };
      expect(noirTypeToString(aztecAddress)).toBe("AztecAddress");
    });

    it("should convert boolean type", () => {
      const bool = {
        name: "test",
        type: { kind: "boolean" as const },
        visibility: "public" as const,
      };
      expect(noirTypeToString(bool)).toBe("bool");
    });
  });

  describe("argsToFields", () => {
    it("should convert various types to bigint", () => {
      const args = [
        123n, // bigint
        456, // number
        true, // boolean
        "789", // string number
        "0xabc", // hex string
        { toBigInt: () => 999n }, // Fr-like
      ];

      const fields = argsToFields(args);

      expect(fields).toEqual([123n, 456n, 1n, 789n, 0xabcn, 999n]);
    });

    it("should handle AztecAddress-like objects", () => {
      const aztecAddress = {
        toField: () => ({ toBigInt: () => 12345n }),
      };

      const fields = argsToFields([aztecAddress]);
      expect(fields).toEqual([12345n]);
    });
  });
});
