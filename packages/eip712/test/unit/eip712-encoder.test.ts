/**
 * Unit tests for EIP-712 Encoder
 */

import { describe, it, expect } from "vitest";
import {
  Eip712Encoder,
  DEFAULT_APP_DOMAIN,
  TYPE_HASHES,
} from "../../src/lib/eip712-encoder";
import {
  MAX_SERIALIZED_ARGS,
  MAX_SIGNATURE_SIZE,
} from "../../src/lib/eip712-types";
import {
  EMPTY_FUNCTION_CALL,
  ACCOUNT_MAX_CALLS,
  DEFAULT_VERIFYING_CONTRACT,
  type FunctionCall,
} from "../../src/lib/eip712-types";

describe("Eip712Encoder", () => {
  describe("constructor", () => {
    it("should use default chain ID 31337", () => {
      const encoder = new Eip712Encoder();
      const typedData = encoder.buildEntrypointTypedData5([], 0n);
      expect(typedData.domain.chainId).toBe(31337n);
    });

    it("should accept custom chain ID", () => {
      const encoder = new Eip712Encoder({ chainId: 1n });
      const typedData = encoder.buildEntrypointTypedData5([], 0n);
      expect(typedData.domain.chainId).toBe(1n);
    });

    it("should accept custom app domain", () => {
      const encoder = new Eip712Encoder({
        appDomain: { name: "Custom Wallet" },
      });
      const typedData = encoder.buildEntrypointTypedData5([], 0n);
      expect(typedData.message.appDomain.name).toBe("Custom Wallet");
    });
  });

  describe("createFunctionCall", () => {
    it("should create function call from bigint address", () => {
      const call = Eip712Encoder.createFunctionCall(
        123n,
        "transfer(Field,u128)",
        [456n, 789n],
      );

      expect(call.contract).toMatch(/^0x/);
      expect(call.functionSignature).toBe("transfer(Field,u128)");
      expect(call.arguments).toEqual([456n, 789n]);
    });

    it("should create function call from hex address", () => {
      const call = Eip712Encoder.createFunctionCall("0x1234", "mint(Field)", [
        100n,
      ]);

      expect(call.contract).toMatch(/^0x/);
      expect(call.functionSignature).toBe("mint(Field)");
      expect(call.arguments).toEqual([100n]);
    });

    it("should throw if too many arguments", () => {
      const args = Array(MAX_SERIALIZED_ARGS + 1).fill(0n);
      expect(() =>
        Eip712Encoder.createFunctionCall(0n, "test()", args),
      ).toThrow(`Too many arguments: ${MAX_SERIALIZED_ARGS + 1}`);
    });

    it("should throw if function signature too long", () => {
      const longSig = "a".repeat(MAX_SIGNATURE_SIZE + 1);
      expect(() => Eip712Encoder.createFunctionCall(0n, longSig, [])).toThrow(
        `Function signature too long: ${MAX_SIGNATURE_SIZE + 1}`,
      );
    });
  });

  describe("buildEntrypointTypedData5", () => {
    it("should pad to 5 function calls", () => {
      const encoder = new Eip712Encoder();
      const call = Eip712Encoder.createFunctionCall(1n, "test()", []);
      const typedData = encoder.buildEntrypointTypedData5([call], 1n);

      expect(typedData.message.functionCalls).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(typedData.message.functionCalls[0]).toEqual(call);
      // Remaining should be empty
      for (let i = 1; i < ACCOUNT_MAX_CALLS; i++) {
        expect(typedData.message.functionCalls[i]).toEqual(EMPTY_FUNCTION_CALL);
      }
    });

    it("should throw if more than 5 calls", () => {
      const encoder = new Eip712Encoder();
      const calls = Array(6)
        .fill(null)
        .map((_, i) =>
          Eip712Encoder.createFunctionCall(BigInt(i), "test()", []),
        );

      expect(() => encoder.buildEntrypointTypedData5(calls, 0n)).toThrow(
        `Too many function calls: 6 > ${ACCOUNT_MAX_CALLS}`,
      );
    });

    it("should include correct primary type", () => {
      const encoder = new Eip712Encoder();
      const typedData = encoder.buildEntrypointTypedData5([], 0n);

      expect(typedData.primaryType).toBe("EntrypointAuthorization");
    });

    it("should include tx nonce in message", () => {
      const encoder = new Eip712Encoder();
      const typedData = encoder.buildEntrypointTypedData5([], 42n);

      expect(typedData.message.txNonce).toBe(42n);
    });

    it("should use provided verifying contract", () => {
      const encoder = new Eip712Encoder();
      const customContract = "0xdeadbeef00000000000000000000000000000000";
      const typedData = encoder.buildEntrypointTypedData5(
        [],
        0n,
        customContract,
      );

      expect(typedData.domain.verifyingContract).toBe(customContract);
    });
  });

  describe("buildAuthwitTypedData", () => {
    it("should build authwit typed data for single call", () => {
      const encoder = new Eip712Encoder();
      const call = Eip712Encoder.createFunctionCall(
        123n,
        "transfer_from(Field,Field,u128)",
        [1n, 2n, 100n],
      );
      const verifyingContract = "0x1234567890123456789012345678901234567890";
      const typedData = encoder.buildAuthwitTypedData(call, verifyingContract);

      expect(typedData.primaryType).toBe("FunctionCallAuthorization");
      expect(typedData.message.functionCall).toEqual(call);
      expect(typedData.domain.verifyingContract).toBe(verifyingContract);
    });
  });

  describe("hash functions", () => {
    it("should compute consistent function call hash", () => {
      const call = Eip712Encoder.createFunctionCall(
        123n,
        "transfer(Field,u128)",
        [456n, 789n],
      );
      const hash1 = Eip712Encoder.hashFunctionCall(call);
      const hash2 = Eip712Encoder.hashFunctionCall(call);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("should compute different hashes for different calls", () => {
      const call1 = Eip712Encoder.createFunctionCall(123n, "transfer()", []);
      const call2 = Eip712Encoder.createFunctionCall(456n, "transfer()", []);

      expect(Eip712Encoder.hashFunctionCall(call1)).not.toBe(
        Eip712Encoder.hashFunctionCall(call2),
      );
    });

    it("should compute app domain hash", () => {
      const hash = Eip712Encoder.hashAppDomain(DEFAULT_APP_DOMAIN);

      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("should compute function calls array hash", () => {
      const calls: FunctionCall[] = Array(ACCOUNT_MAX_CALLS)
        .fill(null)
        .map(() => EMPTY_FUNCTION_CALL);

      const hash = Eip712Encoder.hashFunctionCallsArray(calls);
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("should throw if function calls array wrong length", () => {
      const calls = [EMPTY_FUNCTION_CALL];
      expect(() => Eip712Encoder.hashFunctionCallsArray(calls)).toThrow(
        `Expected ${ACCOUNT_MAX_CALLS} calls, got 1`,
      );
    });

    it("should compute domain separator with contract", () => {
      const separator = Eip712Encoder.computeDomainSeparatorWithContract(
        31337n,
        DEFAULT_VERIFYING_CONTRACT,
      );

      expect(separator).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("TYPE_HASHES", () => {
    it("should have all required type hashes", () => {
      expect(TYPE_HASHES.FUNCTION_CALL).toMatch(/^0x[0-9a-f]{64}$/);
      expect(TYPE_HASHES.APP_DOMAIN).toMatch(/^0x[0-9a-f]{64}$/);
      expect(TYPE_HASHES.ENTRYPOINT_AUTHORIZATION_5).toMatch(
        /^0x[0-9a-f]{64}$/,
      );
      expect(TYPE_HASHES.AUTHWIT_APP_DOMAIN).toMatch(/^0x[0-9a-f]{64}$/);
      expect(TYPE_HASHES.FUNCTION_CALL_AUTHORIZATION).toMatch(
        /^0x[0-9a-f]{64}$/,
      );
    });
  });

  describe("getNoirConstants", () => {
    it("should return pre-computed hashes", () => {
      const constants = Eip712Encoder.getNoirConstants();

      expect(constants.appDomainNameHash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(constants.appDomainVersionHash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(constants.domainSeparator).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });
});
