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
  MERKLE_ROOT_ARGUMENTS,
  MERKLE_ROOT_ARGUMENTS1,
  MERKLE_ROOT_ARGUMENTS2,
  MERKLE_DEPTH,
} from "../../src/lib/merkle-tree-data.js";
import {
  buildArgumentsTypeString,
  FC1_PRIMARY,
  FC2_PRIMARY,
  FC_AUTH_PRIMARY,
  AUTHWIT_APP_DOMAIN_DEF,
  type ArgumentType,
} from "../../src/lib/eip712-types-v2.js";

/** BN254 scalar field modulus (same as in merkle-tree-data.ts) */
const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

describe("Merkle Trees", () => {
  describe("getMerkleRoot", () => {
    it("should return correct root for Arguments", () => {
      expect(getMerkleRoot("Arguments")).toBe(MERKLE_ROOT_ARGUMENTS);
    });

    it("should return correct root for Arguments1", () => {
      expect(getMerkleRoot("Arguments1")).toBe(MERKLE_ROOT_ARGUMENTS1);
    });

    it("should return correct root for Arguments2", () => {
      expect(getMerkleRoot("Arguments2")).toBe(MERKLE_ROOT_ARGUMENTS2);
    });

    it("should throw for unknown struct name", () => {
      expect(() => getMerkleRoot("UnknownStruct")).toThrow(
        "Unknown struct name: UnknownStruct",
      );
    });

    it("roots should be valid hex strings", () => {
      expect(MERKLE_ROOT_ARGUMENTS).toMatch(/^0x[0-9a-f]{64}$/);
      expect(MERKLE_ROOT_ARGUMENTS1).toMatch(/^0x[0-9a-f]{64}$/);
      expect(MERKLE_ROOT_ARGUMENTS2).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("computeFcTypeHashField (Approach 2)", () => {
    it("should match manual keccak256(fc_encode_type) → Field for Arguments (authwit)", () => {
      const argTypes: ArgumentType[] = ["bytes32", "uint256"];
      const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);
      const fcEncodeType = FC_AUTH_PRIMARY + argsTypeString + AUTHWIT_APP_DOMAIN_DEF;
      const hash = keccak256(encodePacked(["string"], [fcEncodeType]));
      const expectedField = new Fr(BigInt(hash) % BN254_FR_MODULUS);

      const actual = computeFcTypeHashField("Arguments", argTypes);
      expect(actual.toBigInt()).toBe(expectedField.toBigInt());
    });

    it("should match manual keccak256(fc_encode_type) → Field for Arguments1", () => {
      const argTypes: ArgumentType[] = ["bytes32"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const fcEncodeType = FC1_PRIMARY + argsTypeString;
      const hash = keccak256(encodePacked(["string"], [fcEncodeType]));
      const expectedField = new Fr(BigInt(hash) % BN254_FR_MODULUS);

      const actual = computeFcTypeHashField("Arguments1", argTypes);
      expect(actual.toBigInt()).toBe(expectedField.toBigInt());
    });

    it("should match for empty args (Arguments1)", () => {
      const argsTypeString = buildArgumentsTypeString("Arguments1", []);
      const fcEncodeType = FC1_PRIMARY + argsTypeString;
      const hash = keccak256(encodePacked(["string"], [fcEncodeType]));
      const expectedField = new Fr(BigInt(hash) % BN254_FR_MODULUS);

      const actual = computeFcTypeHashField("Arguments1", []);
      expect(actual.toBigInt()).toBe(expectedField.toBigInt());
    });

    it("should produce different fields for different type combos", () => {
      const field1 = computeFcTypeHashField("Arguments", ["bytes32"]);
      const field2 = computeFcTypeHashField("Arguments", ["uint256"]);
      const field3 = computeFcTypeHashField("Arguments", ["int256"]);

      expect(field1.toBigInt()).not.toBe(field2.toBigInt());
      expect(field2.toBigInt()).not.toBe(field3.toBigInt());
      expect(field1.toBigInt()).not.toBe(field3.toBigInt());
    });

    it("should produce same result for same inputs", () => {
      const field1 = computeFcTypeHashField("Arguments2", [
        "bytes32",
        "int256",
      ]);
      const field2 = computeFcTypeHashField("Arguments2", [
        "bytes32",
        "int256",
      ]);
      expect(field1.toBigInt()).toBe(field2.toBigInt());
    });
  });

  describe("computeFcTypeHashBytes / computeArgsTypeHashBytes", () => {
    it("computeFcTypeHashBytes returns raw keccak256 of fc_encode_type", () => {
      const argTypes: ArgumentType[] = ["uint256"];
      const argsTypeString = buildArgumentsTypeString("Arguments2", argTypes);
      const fcEncodeType = FC2_PRIMARY + argsTypeString;
      const expected = keccak256(encodePacked(["string"], [fcEncodeType]));

      const actual = computeFcTypeHashBytes("Arguments2", argTypes);
      expect(actual.toLowerCase()).toBe(expected.toLowerCase());
    });

    it("computeArgsTypeHashBytes returns raw keccak256 of args_type_string", () => {
      const argTypes: ArgumentType[] = ["bytes32", "int256"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const expected = keccak256(encodePacked(["string"], [argsTypeString]));

      const actual = computeArgsTypeHashBytes("Arguments1", argTypes);
      expect(actual.toLowerCase()).toBe(expected.toLowerCase());
    });
  });

  describe("getMerkleProof", () => {
    it("should return valid proof for single bytes32 arg", async () => {
      const proof = await getMerkleProof("Arguments", ["bytes32"]);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
      proof.siblingPath.forEach((node) => {
        expect(node).toBeInstanceOf(Fr);
      });
    });

    it("should return valid proof for Arguments1 with mixed types", async () => {
      const proof = await getMerkleProof("Arguments1", [
        "bytes32",
        "uint256",
        "int256",
      ]);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return valid proof for Arguments2 with single arg", async () => {
      const proof = await getMerkleProof("Arguments2", ["uint256"]);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return valid proof for empty Arguments (0 args)", async () => {
      const proof = await getMerkleProof("Arguments", []);

      expect(proof.leafIndex).toBe(0); // Empty args should be first leaf
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return valid proof for max Arguments (10 args)", async () => {
      const argTypes: ArgumentType[] = Array(10).fill("uint256");
      const proof = await getMerkleProof("Arguments", argTypes);

      expect(proof.leafIndex).toBeGreaterThanOrEqual(0);
      expect(proof.siblingPath).toHaveLength(MERKLE_DEPTH);
    });

    it("should return consistent proofs for the same input", async () => {
      const proof1 = await getMerkleProof("Arguments1", [
        "bytes32",
        "uint256",
      ]);
      const proof2 = await getMerkleProof("Arguments1", [
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
  });
});
