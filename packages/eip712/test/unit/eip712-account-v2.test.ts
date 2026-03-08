/**
 * Unit tests for EIP-712 V2 Account
 */

import { describe, it, expect } from "vitest";
import {
  Eip712AccountV2,
  createEip712AccountV2,
  generateEip712AccountV2,
  type FunctionCallInputV2,
} from "../../src/lib/eip712-account-v2.js";
import { AztecAddress } from "@aztec/aztec.js/addresses";

describe("Eip712AccountV2", () => {
  const TEST_PRIVATE_KEY =
    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  describe("constructor", () => {
    it("should create account with provided private key", () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const pubKey = account.getPublicKey();

      expect(pubKey.x).toHaveLength(32);
      expect(pubKey.y).toHaveLength(32);
    });

    it("should generate random key if not provided", () => {
      const account1 = new Eip712AccountV2();
      const account2 = new Eip712AccountV2();

      expect(account1.getPublicKey().x).not.toEqual(
        account2.getPublicKey().x,
      );
    });

    it("should use default chain ID 31337", () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      expect(account.chainId).toBe(31337n);
    });

    it("should use provided chain ID", () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY, 1n);
      expect(account.chainId).toBe(1n);
    });
  });

  describe("getPublicKey", () => {
    it("should return 32-byte x and y coordinates", () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const pubKey = account.getPublicKey();

      expect(pubKey.x).toBeInstanceOf(Uint8Array);
      expect(pubKey.y).toBeInstanceOf(Uint8Array);
      expect(pubKey.x.length).toBe(32);
      expect(pubKey.y.length).toBe(32);
    });

    it("should return consistent keys for same private key", () => {
      const account1 = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const account2 = new Eip712AccountV2(TEST_PRIVATE_KEY);

      expect(account1.getPublicKey().x).toEqual(account2.getPublicKey().x);
      expect(account1.getPublicKey().y).toEqual(account2.getPublicKey().y);
    });
  });

  describe("getPublicKeyArrays", () => {
    it("should return number arrays for contract constructor", () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
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
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const address = account.getEthAddress();

      expect(address).toMatch(/^0x[0-9a-f]{40}$/);
    });

    it("should return consistent address for same key", () => {
      const account1 = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const account2 = new Eip712AccountV2(TEST_PRIVATE_KEY);

      expect(account1.getEthAddress()).toBe(account2.getEthAddress());
    });
  });

  describe("createWitnessCapsule2", () => {
    it("should create capsule with correct contract address", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const call: FunctionCallInputV2 = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
        argTypes: [],
      };
      const capsule = await account.createWitnessCapsule2(
        [call],
        0n,
        contractAddress,
      );

      expect(capsule).toBeDefined();
      expect(capsule.contractAddress.equals(contractAddress)).toBe(true);
    });

    it("should serialize to 79 fields for 1 call", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const call: FunctionCallInputV2 = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
        argTypes: [],
      };
      const capsule = await account.createWitnessCapsule2(
        [call],
        0n,
        contractAddress,
      );

      expect(capsule.data).toHaveLength(79);
    });

    it("should handle single function call", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const call: FunctionCallInputV2 = {
        targetAddress: 123n,
        functionSignature: "transfer(Field,u128)",
        args: [456n, 789n],
        argTypes: ["uint256", "uint256"],
      };
      const capsule = await account.createWitnessCapsule2(
        [call],
        1n,
        contractAddress,
      );

      expect(capsule.data).toHaveLength(79);
    });

    it("should handle two function calls", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const calls: FunctionCallInputV2[] = [
        {
          targetAddress: 1n,
          functionSignature: "func1(Field)",
          args: [100n],
          argTypes: ["uint256"],
        },
        {
          targetAddress: 2n,
          functionSignature: "func2(Field,Field)",
          args: [200n, 300n],
          argTypes: ["uint256", "int256"],
        },
      ];
      const capsule = await account.createWitnessCapsule2(
        calls,
        2n,
        contractAddress,
      );

      expect(capsule.data).toHaveLength(143);
    });

    it("should handle three function calls", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const calls: FunctionCallInputV2[] = [
        {
          targetAddress: 1n,
          functionSignature: "func1(Field)",
          args: [100n],
          argTypes: ["uint256"],
        },
        {
          targetAddress: 2n,
          functionSignature: "func2(Field,Field)",
          args: [200n, 300n],
          argTypes: ["uint256", "int256"],
        },
        {
          targetAddress: 3n,
          functionSignature: "func3(Field)",
          args: [400n],
          argTypes: ["bytes32"],
        },
      ];
      const capsule = await account.createWitnessCapsule2(
        calls,
        3n,
        contractAddress,
      );

      expect(capsule.data).toHaveLength(207);
    });

    it("should throw for empty calls", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);

      await expect(
        account.createWitnessCapsule2([], 0n, contractAddress),
      ).rejects.toThrow("At least one call is required");
    });

    it("should throw if more than 4 calls", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const calls: FunctionCallInputV2[] = [
        {
          targetAddress: 1n,
          functionSignature: "func1()",
          args: [],
          argTypes: [],
        },
        {
          targetAddress: 2n,
          functionSignature: "func2()",
          args: [],
          argTypes: [],
        },
        {
          targetAddress: 3n,
          functionSignature: "func3()",
          args: [],
          argTypes: [],
        },
        {
          targetAddress: 4n,
          functionSignature: "func4()",
          args: [],
          argTypes: [],
        },
        {
          targetAddress: 5n,
          functionSignature: "func5()",
          args: [],
          argTypes: [],
        },
      ];

      await expect(
        account.createWitnessCapsule2(calls, 0n, contractAddress),
      ).rejects.toThrow("Too many calls: 5 > 4");
    });
  });

  describe("createAuthwitCapsuleV2", () => {
    it("should create authwit capsule with correct contract address", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(888n);
      const call: FunctionCallInputV2 = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
        argTypes: [],
      };
      const capsule = await account.createAuthwitCapsuleV2(
        call,
        "0x0000000000000000000000000000000000000001",
        contractAddress,
      );

      expect(capsule).toBeDefined();
      expect(capsule.contractAddress.equals(contractAddress)).toBe(true);
    });

    it("should serialize to 67 fields", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(888n);
      const call: FunctionCallInputV2 = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
        argTypes: [],
      };
      const capsule = await account.createAuthwitCapsuleV2(
        call,
        "0x0000000000000000000000000000000000000001",
        contractAddress,
      );

      expect(capsule.data).toHaveLength(67);
    });

    it("should handle call with arguments", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(888n);
      const call: FunctionCallInputV2 = {
        targetAddress: 123n,
        functionSignature: "transfer_from(Field,Field,u128)",
        args: [1n, 2n, 100n],
        argTypes: ["uint256", "uint256", "uint256"],
      };
      const capsule = await account.createAuthwitCapsuleV2(
        call,
        "0x0000000000000000000000000000000000000001",
        contractAddress,
      );

      expect(capsule.data).toHaveLength(67);
    });

    it("should include inner hash", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(888n);
      const call: FunctionCallInputV2 = {
        targetAddress: 1n,
        functionSignature: "test()",
        args: [],
        argTypes: [],
      };
      const innerHash = 12345n;
      const capsule = await account.createAuthwitCapsuleV2(
        call,
        "0x0000000000000000000000000000000000000001",
        contractAddress,
        innerHash,
      );

      // Inner hash is the last field (index 62)
      expect(capsule.data[62].toBigInt()).toBe(innerHash);
    });
  });

  describe("factory functions", () => {
    it("createEip712AccountV2 should create account from private key", () => {
      const account = createEip712AccountV2(TEST_PRIVATE_KEY);
      expect(account).toBeInstanceOf(Eip712AccountV2);
      expect(account.getEthAddress()).toMatch(/^0x[0-9a-f]{40}$/);
    });

    it("createEip712AccountV2 should accept chain ID", () => {
      const account = createEip712AccountV2(TEST_PRIVATE_KEY, 1n);
      expect(account).toBeInstanceOf(Eip712AccountV2);
      expect(account.chainId).toBe(1n);
    });

    it("generateEip712AccountV2 should create random account", () => {
      const account1 = generateEip712AccountV2();
      const account2 = generateEip712AccountV2();

      expect(account1).toBeInstanceOf(Eip712AccountV2);
      expect(account2).toBeInstanceOf(Eip712AccountV2);
      expect(account1.getEthAddress()).not.toBe(account2.getEthAddress());
    });

    it("generateEip712AccountV2 should accept chain ID", () => {
      const account = generateEip712AccountV2(42n);
      expect(account.chainId).toBe(42n);
    });
  });
});
