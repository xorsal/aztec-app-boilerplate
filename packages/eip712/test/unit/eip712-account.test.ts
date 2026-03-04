/**
 * Unit tests for EIP-712 Account
 */

import { describe, it, expect } from "vitest";
import {
  Eip712Account,
  createEip712Account,
  generateEip712Account,
  type FunctionCallInput,
} from "../../src/lib/eip712-account";
import {
  ACCOUNT_MAX_CALLS,
  MAX_SERIALIZED_ARGS,
  MAX_SIGNATURE_SIZE,
  EIP712_WITNESS_5_SERIALIZED_LEN,
  EIP712_AUTHWIT_SERIALIZED_LEN,
} from "../../src/lib/eip712-types";
import { AztecAddress } from "@aztec/aztec.js/addresses";

describe("Eip712Account", () => {
  const TEST_PRIVATE_KEY =
    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  describe("constructor", () => {
    it("should create account with provided private key", () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const pubKey = account.getPublicKey();

      expect(pubKey.x).toHaveLength(32);
      expect(pubKey.y).toHaveLength(32);
    });

    it("should generate random key if not provided", () => {
      const account1 = new Eip712Account();
      const account2 = new Eip712Account();

      // Different accounts should have different public keys
      expect(account1.getPublicKey().x).not.toEqual(account2.getPublicKey().x);
    });

    it("should use provided chain ID", () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY, 1n);
      // Chain ID is used internally for signing
      expect(account).toBeDefined();
    });
  });

  describe("getPublicKey", () => {
    it("should return 32-byte x and y coordinates", () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const pubKey = account.getPublicKey();

      expect(pubKey.x).toBeInstanceOf(Uint8Array);
      expect(pubKey.y).toBeInstanceOf(Uint8Array);
      expect(pubKey.x.length).toBe(32);
      expect(pubKey.y.length).toBe(32);
    });
  });

  describe("getPublicKeyArrays", () => {
    it("should return number arrays for contract constructor", () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const arrays = account.getPublicKeyArrays();

      expect(Array.isArray(arrays.x)).toBe(true);
      expect(Array.isArray(arrays.y)).toBe(true);
      expect(arrays.x.length).toBe(32);
      expect(arrays.y.length).toBe(32);
      arrays.x.forEach((v) => expect(typeof v).toBe("number"));
      arrays.y.forEach((v) => expect(typeof v).toBe("number"));
    });
  });

  describe("getEthAddress", () => {
    it("should return valid Ethereum address", () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const address = account.getEthAddress();

      expect(address).toMatch(/^0x[0-9a-f]{40}$/);
    });

    it("should return consistent address for same key", () => {
      const account1 = new Eip712Account(TEST_PRIVATE_KEY);
      const account2 = new Eip712Account(TEST_PRIVATE_KEY);

      expect(account1.getEthAddress()).toBe(account2.getEthAddress());
    });
  });

  describe("signEntrypoint5", () => {
    it("should sign empty call list", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const oracleData = await account.signEntrypoint5([], 0n);

      expect(oracleData.ecdsaSignature).toHaveLength(64);
      expect(oracleData.functionSignatures).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.signatureLengths).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.functionArgs).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.argsLengths).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.targetAddresses).toHaveLength(ACCOUNT_MAX_CALLS);
    });

    it("should sign single function call", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const call: FunctionCallInput = {
        targetAddress: 123n,
        functionSignature: "transfer(Field,u128)",
        args: [456n, 789n],
      };
      const oracleData = await account.signEntrypoint5([call], 1n);

      expect(oracleData.ecdsaSignature).toHaveLength(64);
      expect(oracleData.targetAddresses[0]).toBe(123n);
      expect(oracleData.signatureLengths[0]).toBe(
        "transfer(Field,u128)".length,
      );
      expect(oracleData.argsLengths[0]).toBe(2);
    });

    it("should sign multiple function calls", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const calls: FunctionCallInput[] = [
        { targetAddress: 1n, functionSignature: "func1()", args: [100n] },
        { targetAddress: 2n, functionSignature: "func2()", args: [200n, 300n] },
        { targetAddress: 3n, functionSignature: "func3()", args: [] },
      ];
      const oracleData = await account.signEntrypoint5(calls, 2n);

      expect(oracleData.targetAddresses[0]).toBe(1n);
      expect(oracleData.targetAddresses[1]).toBe(2n);
      expect(oracleData.targetAddresses[2]).toBe(3n);
      expect(oracleData.argsLengths[0]).toBe(1);
      expect(oracleData.argsLengths[1]).toBe(2);
      expect(oracleData.argsLengths[2]).toBe(0);
    });

    it("should throw if more than 5 calls", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const calls = Array(6)
        .fill(null)
        .map((_, i) => ({
          targetAddress: BigInt(i),
          functionSignature: `func${i}()`,
          args: [],
        }));

      await expect(account.signEntrypoint5(calls, 0n)).rejects.toThrow(
        `Too many calls: 6 > ${ACCOUNT_MAX_CALLS}`,
      );
    });

    it("should pad function args to MAX_SERIALIZED_ARGS", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const call: FunctionCallInput = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [1n, 2n],
      };
      const oracleData = await account.signEntrypoint5([call], 0n);

      expect(oracleData.functionArgs[0]).toHaveLength(MAX_SERIALIZED_ARGS);
      expect(oracleData.functionArgs[0][0]).toBe(1n);
      expect(oracleData.functionArgs[0][1]).toBe(2n);
      expect(oracleData.functionArgs[0][2]).toBe(0n);
    });

    it("should pad function signature to MAX_SIGNATURE_SIZE", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const call: FunctionCallInput = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
      };
      const oracleData = await account.signEntrypoint5([call], 0n);

      expect(oracleData.functionSignatures[0]).toHaveLength(MAX_SIGNATURE_SIZE);
    });
  });

  describe("signAuthwit", () => {
    it("should sign individual authwit", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const call: FunctionCallInput = {
        targetAddress: 123n,
        functionSignature: "transfer_from(Field,Field,u128)",
        args: [1n, 2n, 100n],
      };
      const verifyingContract = "0x1234567890123456789012345678901234567890";
      const oracleData = await account.signAuthwit(call, verifyingContract);

      expect(oracleData.ecdsaSignature).toHaveLength(64);
      expect(oracleData.targetAddress).toBe(123n);
      expect(oracleData.signatureLength).toBe(call.functionSignature.length);
      expect(oracleData.argsLength).toBe(3);
      expect(oracleData.verifyingContract).toBe(BigInt(verifyingContract));
    });

    it("should include inner hash in oracle data", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const call: FunctionCallInput = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
      };
      const innerHash = 12345n;
      const oracleData = await account.signAuthwit(
        call,
        "0x0000000000000000000000000000000000000001",
        innerHash,
      );

      expect(oracleData.innerHash).toBe(innerHash);
    });
  });

  describe("createWitnessCapsule5", () => {
    it("should create capsule with correct slot", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const capsule = await account.createWitnessCapsule5(
        [],
        0n,
        contractAddress,
      );

      expect(capsule).toBeDefined();
      // Capsule should have the contract address and correct slot
      expect(capsule.contractAddress.equals(contractAddress)).toBe(true);
    });

    it("should serialize to correct number of fields", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const capsule = await account.createWitnessCapsule5(
        [],
        0n,
        contractAddress,
      );

      // The capsule data should have EIP712_WITNESS_5_SERIALIZED_LEN fields
      expect(capsule.data).toHaveLength(EIP712_WITNESS_5_SERIALIZED_LEN);
    });
  });

  describe("createAuthwitCapsule", () => {
    it("should create authwit capsule with correct slot", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(888n);
      const call: FunctionCallInput = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
      };
      const capsule = await account.createAuthwitCapsule(
        call,
        "0x0000000000000000000000000000000000000001",
        contractAddress,
      );

      expect(capsule).toBeDefined();
      expect(capsule.contractAddress.equals(contractAddress)).toBe(true);
    });

    it("should serialize to correct number of fields", async () => {
      const account = new Eip712Account(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(888n);
      const call: FunctionCallInput = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
      };
      const capsule = await account.createAuthwitCapsule(
        call,
        "0x0000000000000000000000000000000000000001",
        contractAddress,
      );

      expect(capsule.data).toHaveLength(EIP712_AUTHWIT_SERIALIZED_LEN);
    });
  });

  describe("factory functions", () => {
    it("createEip712Account should create account from private key", () => {
      const account = createEip712Account(TEST_PRIVATE_KEY);
      expect(account).toBeInstanceOf(Eip712Account);
      expect(account.getEthAddress()).toMatch(/^0x[0-9a-f]{40}$/);
    });

    it("createEip712Account should accept chain ID", () => {
      const account = createEip712Account(TEST_PRIVATE_KEY, 1n);
      expect(account).toBeInstanceOf(Eip712Account);
    });

    it("generateEip712Account should create random account", () => {
      const account1 = generateEip712Account();
      const account2 = generateEip712Account();

      expect(account1).toBeInstanceOf(Eip712Account);
      expect(account2).toBeInstanceOf(Eip712Account);
      expect(account1.getEthAddress()).not.toBe(account2.getEthAddress());
    });
  });
});
