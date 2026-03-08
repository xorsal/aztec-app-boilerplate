/**
 * Unit tests for Merkle Tree Data
 */

import { describe, it, expect } from "vitest";
import { keccak256, encodePacked } from "viem";
import { Fr } from "@aztec/aztec.js/fields";
import {
  getMerkleProof,
  getMerkleRoot,
  computeFcTypeHashField,
  computeFcTypeHashBytes,
  computeArgsTypeHashBytes,
  MERKLE_ROOT_FC_1,
  MERKLE_ROOT_FC_2,
  MERKLE_ROOT_FC_3,
  MERKLE_ROOT_FC_4,
  MERKLE_ROOT_FC_AUTH,
  MERKLE_DEPTH,
} from "../../src/lib/merkle-tree-data.js";
import {
  buildArgumentsTypeString,
  FC_PRIMARIES,
  FC_AUTH_PRIMARY,
  AUTHWIT_APP_DOMAIN_DEF,
  type ArgumentType,
} from "../../src/lib/eip712-types-v2.js";

/** BN254 scalar field modulus (same as in merkle-tree-data.ts) */
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

describe("Merkle Trees", () => {
  describe("getMerkleRoot", () => {
    it("should return correct root for FunctionCall1", () => {
      expect(getMerkleRoot("FunctionCall1")).toBe(MERKLE_ROOT_FC_1);
    });

    it("should return correct root for FunctionCall2", () => {
      expect(getMerkleRoot("FunctionCall2")).toBe(MERKLE_ROOT_FC_2);
    });

    it("should return correct root for FunctionCall3", () => {
      expect(getMerkleRoot("FunctionCall3")).toBe(MERKLE_ROOT_FC_3);
    });

    it("should return correct root for FunctionCall4", () => {
      expect(getMerkleRoot("FunctionCall4")).toBe(MERKLE_ROOT_FC_4);
    });

    it("should return correct root for Arguments", () => {
      expect(getMerkleRoot("Arguments")).toBe(MERKLE_ROOT_FC_AUTH);
    });

    it("should throw for unknown struct name", () => {
      expect(() => getMerkleRoot("UnknownStruct")).toThrow(
        "Unknown struct name: UnknownStruct",
      );
    });

    it("roots should be valid hex strings", () => {
      expect(MERKLE_ROOT_FC_1).toMatch(/^0x[0-9a-f]{64}$/);
      expect(MERKLE_ROOT_FC_2).toMatch(/^0x[0-9a-f]{64}$/);
      expect(MERKLE_ROOT_FC_3).toMatch(/^0x[0-9a-f]{64}$/);
      expect(MERKLE_ROOT_FC_4).toMatch(/^0x[0-9a-f]{64}$/);
      expect(MERKLE_ROOT_FC_AUTH).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("computeFcTypeHashField (Approach 2)", () => {
    it("should match manual keccak256(fc_encode_type) → Field for Arguments (authwit)", () => {
      const argTypes: ArgumentType[] = ["bytes32", "uint256"];
      const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
      const fcEncodeType =
        FC_AUTH_PRIMARY + argsTypeString + AUTHWIT_APP_DOMAIN_DEF;
      const hash = keccak256(encodePacked(["string"], [fcEncodeType]));
      const expectedField = new Fr(BigInt(hash) % BN254_FR_MODULUS);

      const actual = computeFcTypeHashField("Arguments", argTypes);
      expect(actual.toBigInt()).toBe(expectedField.toBigInt());
    });

    it("should match manual keccak256(fc_encode_type) → Field for FunctionCall1", () => {
      const argTypes: ArgumentType[] = ["bytes32"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const fcEncodeType = FC_PRIMARIES[1] + argsTypeString;
      const hash = keccak256(encodePacked(["string"], [fcEncodeType]));
      const expectedField = new Fr(BigInt(hash) % BN254_FR_MODULUS);

      const actual = computeFcTypeHashField("FunctionCall1", argTypes);
      expect(actual.toBigInt()).toBe(expectedField.toBigInt());
    });

    it("should match for empty args (FunctionCall1)", () => {
      const argsTypeString = buildArgumentsTypeString("Arguments1", []);
      const fcEncodeType = FC_PRIMARIES[1] + argsTypeString;
      const hash = keccak256(encodePacked(["string"], [fcEncodeType]));
      const expectedField = new Fr(BigInt(hash) % BN254_FR_MODULUS);

      const actual = computeFcTypeHashField("FunctionCall1", []);
      expect(actual.toBigInt()).toBe(expectedField.toBigInt());
    });

    it("should produce different fields for different type combos", () => {
      const field1 = computeFcTypeHashField("Arguments", ["bytes32"]);
      const field2 = computeFcTypeHashField("Arguments", ["uint256"]);
      const field3 = computeFcTypeHashField("Arguments", ["address"]);

      expect(field1.toBigInt()).not.toBe(field2.toBigInt());
      expect(field2.toBigInt()).not.toBe(field3.toBigInt());
      expect(field1.toBigInt()).not.toBe(field3.toBigInt());
    });

    it("should produce same result for same inputs", () => {
      const field1 = computeFcTypeHashField("FunctionCall1", [
        "bytes32",
        "address",
      ]);
      const field2 = computeFcTypeHashField("FunctionCall1", [
        "bytes32",
        "address",
      ]);
      expect(field1.toBigInt()).toBe(field2.toBigInt());
    });
  });

  describe("computeFcTypeHashBytes / computeArgsTypeHashBytes", () => {
    it("computeFcTypeHashBytes returns raw keccak256 of fc_encode_type", () => {
      const argTypes: ArgumentType[] = ["uint256"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const fcEncodeType = FC_PRIMARIES[1] + argsTypeString;
      const expected = keccak256(encodePacked(["string"], [fcEncodeType]));

      const actual = computeFcTypeHashBytes("FunctionCall1", argTypes);
      expect(actual.toLowerCase()).toBe(expected.toLowerCase());
    });

    it("computeArgsTypeHashBytes returns raw keccak256 of args_type_string (authwit, slot 0)", () => {
      const argTypes: ArgumentType[] = ["bytes32", "address"];
      const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
      const expected = keccak256(encodePacked(["string"], [argsTypeString]));

      const actual = computeArgsTypeHashBytes(0, argTypes);
      expect(actual.toLowerCase()).toBe(expected.toLowerCase());
    });

    it("computeArgsTypeHashBytes returns raw keccak256 of args_type_string (entrypoint, slot 1)", () => {
      const argTypes: ArgumentType[] = ["bytes32", "address"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const expected = keccak256(encodePacked(["string"], [argsTypeString]));

      const actual = computeArgsTypeHashBytes(1, argTypes);
      expect(actual.toLowerCase()).toBe(expected.toLowerCase());
    });
  });

  describe("getMerkleProof", () => {
    it("should return valid proof for single bytes32 arg (JSON path)", async () => {
      const proof = await getMerkleProof("Arguments", ["bytes32"]);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
      proof.siblingPath.forEach((node) => {
        expect(node).toBeInstanceOf(Fr);
      });
    });

    it("should return valid proof for FunctionCall1 with mixed types (JSON path)", async () => {
      const proof = await getMerkleProof("FunctionCall1", [
        "bytes32",
        "uint256",
        "address",
      ]);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return valid proof for Arguments with single arg (JSON path)", async () => {
      const proof = await getMerkleProof("Arguments", ["uint256"]);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return valid proof for empty args (0 args, JSON path)", async () => {
      const proof = await getMerkleProof("FunctionCall1", []);

      expect(proof.leafIndex).toBe(0); // Empty args should be first leaf
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return valid proof for max args (5 args)", async () => {
      const argTypes: ArgumentType[] = Array(5).fill("uint256");
      const proof = await getMerkleProof("Arguments", argTypes);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return consistent proofs for the same input", async () => {
      const proof1 = await getMerkleProof("FunctionCall1", [
        "bytes32",
        "uint256",
      ]);
      const proof2 = await getMerkleProof("FunctionCall1", [
        "bytes32",
        "uint256",
      ]);

      expect(proof1.leafIndex).toBe(proof2.leafIndex);
      for (let i = 0; i < MERKLE_DEPTH; i++) {
        expect(proof1.siblingPath[i].toBigInt()).toBe(
          proof2.siblingPath[i].toBigInt(),
        );
      }
    });

    it("should return different proofs for different type combos", async () => {
      const proof1 = await getMerkleProof("Arguments", ["bytes32"]);
      const proof2 = await getMerkleProof("Arguments", ["uint256"]);

      expect(proof1.leafIndex).not.toBe(proof2.leafIndex);
    });

    it("should throw for arg count exceeding MAX_ARGS", () => {
      const argTypes: ArgumentType[] = Array(6).fill("bytes32");
      expect(() => getMerkleProof("FunctionCall1", argTypes)).toThrow();
    });
  });
});
