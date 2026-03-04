/**
 * EIP-712 Noir Compatibility Tests
 *
 * These tests verify that TypeScript computations match Noir constants exactly.
 * This is critical for signature verification to work across the boundary.
 */

import { describe, it, expect } from "vitest";
import { keccak256, encodePacked, concat, pad, toHex } from "viem";
import {
  Eip712Encoder,
  DEFAULT_APP_DOMAIN,
  TYPE_HASHES,
} from "../../src/lib/eip712-encoder.js";
import {
  EMPTY_FUNCTION_CALL,
  DEFAULT_VERIFYING_CONTRACT,
  EIP712_WITNESS_5_SLOT,
  EIP712_AUTHWIT_SLOT,
} from "../../src/lib/eip712-types.js";

/**
 * Noir constants (copied from contracts/eip712_account/src/eip712.nr and main.nr)
 * These are the ground truth values that TypeScript must match.
 *
 * NOTE: selector is NOT included in FunctionCall - it's derived from functionSignature via Poseidon2:
 * FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)
 */
const NOIR_CONSTANTS = {
  // From eip712.nr (selector NOT included - derived from functionSignature via Poseidon2)
  // FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)
  FUNCTION_CALL_TYPE_HASH:
    "0xbcb4425587c55d02213940c31e3932ab28677442f78c4d1512a6d66bf6d96e86",
  APP_DOMAIN_TYPE_HASH:
    "0xca2212a93d16a0157ab9c731e0ce9d0ae0cb4571382c7bfe48f9af5d2cd4d9f7",
  ENTRYPOINT_AUTHORIZATION_5_TYPE_HASH:
    "0xc984d9563226802b62df861b317094ab6673547312fe52b8caa2b767ad3ad9e7",
  AUTHWIT_APP_DOMAIN_TYPE_HASH:
    "0xa3789202450c418990e2372423a0a0e54a0d058dc6d9383200ef42ba7771668c",
  FUNCTION_CALL_AUTHORIZATION_TYPE_HASH:
    "0x08d98e4671b917579fdc624cd564ad4a1dc72991e645f712654ba28219ffb5e1",
  EMPTY_FUNCTION_CALL_HASH:
    "0x7a9f1abed0f17be296360bf40aff57239ffff0bd193d2e7cb1046a5e14cf8846",

  // From main.nr
  APP_DOMAIN_NAME_HASH:
    "0x35e6e01869e84854dd0110c3f3338dda29499ea7e62e4338336555bee52ea8e9",
  APP_DOMAIN_VERSION_HASH:
    "0x06c015bd22b4c69690933c1058878ebdfef31f9aaae40bbe86d8a09fe1b2972c",
  DOMAIN_SEPARATOR:
    "0x0c4d2d20583d2ee0c940ac2789fd85e2758be2b7546e627efa99bab898e5a141",

  // Capsule slots
  EIP712_WITNESS_5_SLOT: 0x1234567890abcdf0n,
  EIP712_AUTHWIT_SLOT: 0xabcdef1234567890n,
};

describe("EIP-712 Noir Compatibility", () => {
  describe("Type Hashes", () => {
    it("FUNCTION_CALL type hash should match Noir", () => {
      // Note: selector is NOT included - it's derived from functionSignature via Poseidon2
      const computed = keccak256(
        encodePacked(
          ["string"],
          [
            "FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)",
          ],
        ),
      );
      expect(computed.toLowerCase()).toBe(
        NOIR_CONSTANTS.FUNCTION_CALL_TYPE_HASH.toLowerCase(),
      );
      expect(TYPE_HASHES.FUNCTION_CALL.toLowerCase()).toBe(
        NOIR_CONSTANTS.FUNCTION_CALL_TYPE_HASH.toLowerCase(),
      );
    });

    it("APP_DOMAIN type hash should match Noir", () => {
      const computed = keccak256(
        encodePacked(
          ["string"],
          [
            "AppDomain(string name,string version,uint256 chainId,bytes32 salt)",
          ],
        ),
      );
      expect(computed.toLowerCase()).toBe(
        NOIR_CONSTANTS.APP_DOMAIN_TYPE_HASH.toLowerCase(),
      );
      expect(TYPE_HASHES.APP_DOMAIN.toLowerCase()).toBe(
        NOIR_CONSTANTS.APP_DOMAIN_TYPE_HASH.toLowerCase(),
      );
    });

    it("ENTRYPOINT_AUTHORIZATION_5 type hash should match Noir", () => {
      // Note: selector is NOT included in FunctionCall
      const typeString =
        "EntrypointAuthorization(AppDomain appDomain,FunctionCall[5] functionCalls,uint256 txNonce)" +
        "AppDomain(string name,string version,uint256 chainId,bytes32 salt)" +
        "FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)";
      const computed = keccak256(encodePacked(["string"], [typeString]));
      expect(computed.toLowerCase()).toBe(
        NOIR_CONSTANTS.ENTRYPOINT_AUTHORIZATION_5_TYPE_HASH.toLowerCase(),
      );
      expect(TYPE_HASHES.ENTRYPOINT_AUTHORIZATION_5.toLowerCase()).toBe(
        NOIR_CONSTANTS.ENTRYPOINT_AUTHORIZATION_5_TYPE_HASH.toLowerCase(),
      );
    });

    it("AUTHWIT_APP_DOMAIN type hash should match Noir", () => {
      const computed = keccak256(
        encodePacked(
          ["string"],
          ["AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)"],
        ),
      );
      expect(computed.toLowerCase()).toBe(
        NOIR_CONSTANTS.AUTHWIT_APP_DOMAIN_TYPE_HASH.toLowerCase(),
      );
      expect(TYPE_HASHES.AUTHWIT_APP_DOMAIN.toLowerCase()).toBe(
        NOIR_CONSTANTS.AUTHWIT_APP_DOMAIN_TYPE_HASH.toLowerCase(),
      );
    });

    it("FUNCTION_CALL_AUTHORIZATION type hash should match Noir", () => {
      // Note: selector is NOT included in FunctionCall
      const typeString =
        "FunctionCallAuthorization(AuthwitAppDomain appDomain,FunctionCall functionCall)" +
        "AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)" +
        "FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)";
      const computed = keccak256(encodePacked(["string"], [typeString]));
      expect(computed.toLowerCase()).toBe(
        NOIR_CONSTANTS.FUNCTION_CALL_AUTHORIZATION_TYPE_HASH.toLowerCase(),
      );
      expect(TYPE_HASHES.FUNCTION_CALL_AUTHORIZATION.toLowerCase()).toBe(
        NOIR_CONSTANTS.FUNCTION_CALL_AUTHORIZATION_TYPE_HASH.toLowerCase(),
      );
    });
  });

  describe("Pre-computed String Hashes", () => {
    it('APP_DOMAIN_NAME_HASH should match Noir (keccak256("EVM Aztec Wallet"))', () => {
      const computed = keccak256(
        encodePacked(["string"], ["EVM Aztec Wallet"]),
      );
      expect(computed.toLowerCase()).toBe(
        NOIR_CONSTANTS.APP_DOMAIN_NAME_HASH.toLowerCase(),
      );
    });

    it('APP_DOMAIN_VERSION_HASH should match Noir (keccak256("1.0.0"))', () => {
      const computed = keccak256(encodePacked(["string"], ["1.0.0"]));
      expect(computed.toLowerCase()).toBe(
        NOIR_CONSTANTS.APP_DOMAIN_VERSION_HASH.toLowerCase(),
      );
    });

    it("DEFAULT_APP_DOMAIN should use correct name and version", () => {
      expect(DEFAULT_APP_DOMAIN.name).toBe("EVM Aztec Wallet");
      expect(DEFAULT_APP_DOMAIN.version).toBe("1.0.0");
    });
  });

  describe("Domain Separator", () => {
    it("should match Noir DOMAIN_SEPARATOR constant", () => {
      const separator = Eip712Encoder.computeDomainSeparatorWithContract(
        31337n,
        DEFAULT_VERIFYING_CONTRACT,
      );
      expect(separator.toLowerCase()).toBe(
        NOIR_CONSTANTS.DOMAIN_SEPARATOR.toLowerCase(),
      );
    });

    it("should be computed correctly step by step", () => {
      // EIP712Domain type hash
      const domainTypeHash = keccak256(
        encodePacked(
          ["string"],
          [
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
          ],
        ),
      );

      // String hashes
      const nameHash = keccak256(encodePacked(["string"], ["Aztec"]));
      const versionHash = keccak256(encodePacked(["string"], ["1"]));

      // Encode domain separator
      const separator = keccak256(
        concat([
          domainTypeHash,
          nameHash,
          versionHash,
          pad(toHex(31337n), { size: 32 }),
          pad(DEFAULT_VERIFYING_CONTRACT, { size: 32 }),
        ]),
      );

      expect(separator.toLowerCase()).toBe(
        NOIR_CONSTANTS.DOMAIN_SEPARATOR.toLowerCase(),
      );
    });
  });

  describe("Empty Function Call Hash", () => {
    it("should match Noir EMPTY_FUNCTION_CALL_HASH constant", () => {
      const hash = Eip712Encoder.hashFunctionCall(EMPTY_FUNCTION_CALL);
      expect(hash.toLowerCase()).toBe(
        NOIR_CONSTANTS.EMPTY_FUNCTION_CALL_HASH.toLowerCase(),
      );
    });

    it("should be computed correctly step by step", () => {
      // Empty contract (32 zero bytes)
      const emptyContract = pad("0x00", { size: 32 });

      // keccak256("") - empty string hash
      const emptySigHash = keccak256(encodePacked(["string"], [""]));

      // keccak256(0x) - empty bytes hash (same as empty string)
      const emptyArgsHash = keccak256("0x");

      // isPrivate = true (1) for empty function calls
      const isPrivateEncoded = pad(toHex(1n), { size: 32 });

      // Compute hashStruct(FunctionCall) - selector NOT included
      const hash = keccak256(
        concat([
          NOIR_CONSTANTS.FUNCTION_CALL_TYPE_HASH as `0x${string}`,
          emptyContract,
          emptySigHash,
          emptyArgsHash,
          isPrivateEncoded,
        ]),
      );

      expect(hash.toLowerCase()).toBe(
        NOIR_CONSTANTS.EMPTY_FUNCTION_CALL_HASH.toLowerCase(),
      );
    });
  });

  describe("Capsule Slots", () => {
    it("EIP712_WITNESS_5_SLOT should match Noir", () => {
      expect(EIP712_WITNESS_5_SLOT).toBe(NOIR_CONSTANTS.EIP712_WITNESS_5_SLOT);
    });

    it("EIP712_AUTHWIT_SLOT should match Noir", () => {
      expect(EIP712_AUTHWIT_SLOT).toBe(NOIR_CONSTANTS.EIP712_AUTHWIT_SLOT);
    });
  });

  describe("App Domain Hash Computation", () => {
    it("should compute app domain hash correctly", () => {
      // This tests the full app domain hash computation
      const nameHash = keccak256(
        encodePacked(["string"], [DEFAULT_APP_DOMAIN.name]),
      );
      const versionHash = keccak256(
        encodePacked(["string"], [DEFAULT_APP_DOMAIN.version]),
      );

      const appDomainHash = keccak256(
        concat([
          NOIR_CONSTANTS.APP_DOMAIN_TYPE_HASH as `0x${string}`,
          nameHash,
          versionHash,
          pad(toHex(DEFAULT_APP_DOMAIN.chainId), { size: 32 }),
          DEFAULT_APP_DOMAIN.salt as `0x${string}`,
        ]),
      );

      // Verify it matches the encoder's computation
      const encoderHash = Eip712Encoder.hashAppDomain(DEFAULT_APP_DOMAIN);
      expect(encoderHash.toLowerCase()).toBe(appDomainHash.toLowerCase());
    });
  });

  describe("Function Call Hash Computation", () => {
    it("should compute function call hash correctly for a sample call", () => {
      const targetAddress = 123n;
      const functionSignature = "transfer(Field,u128)";
      const args = [456n, 789n];
      const isPrivate = true; // Default for createFunctionCall

      // Manual computation - selector NOT included
      const contract = pad(toHex(targetAddress), { size: 32 });
      const sigHash = keccak256(encodePacked(["string"], [functionSignature]));
      const argsEncoded = concat(
        args.map((arg) => pad(toHex(arg), { size: 32 })),
      );
      const argsHash = keccak256(argsEncoded);
      const isPrivateEncoded = pad(toHex(isPrivate ? 1n : 0n), { size: 32 });

      const manualHash = keccak256(
        concat([
          NOIR_CONSTANTS.FUNCTION_CALL_TYPE_HASH as `0x${string}`,
          contract,
          sigHash,
          argsHash,
          isPrivateEncoded,
        ]),
      );

      // Encoder computation (isPrivate defaults to true)
      const call = Eip712Encoder.createFunctionCall(
        targetAddress,
        functionSignature,
        args,
      );
      const encoderHash = Eip712Encoder.hashFunctionCall(call);

      expect(encoderHash.toLowerCase()).toBe(manualHash.toLowerCase());
    });

    it("should handle empty arguments correctly", () => {
      const call = Eip712Encoder.createFunctionCall(1n, "noArgs()", []);
      const hash = Eip712Encoder.hashFunctionCall(call);

      // Verify it's deterministic and valid
      expect(hash).toMatch(/^0x[0-9a-f]{64}$/);

      // Compute manually (isPrivate defaults to true) - selector NOT included
      const contract = pad(toHex(1n), { size: 32 });
      const sigHash = keccak256(encodePacked(["string"], ["noArgs()"]));
      const emptyArgsHash = keccak256("0x"); // Empty bytes
      const isPrivateEncoded = pad(toHex(1n), { size: 32 }); // true

      const manualHash = keccak256(
        concat([
          NOIR_CONSTANTS.FUNCTION_CALL_TYPE_HASH as `0x${string}`,
          contract,
          sigHash,
          emptyArgsHash,
          isPrivateEncoded,
        ]),
      );

      expect(hash.toLowerCase()).toBe(manualHash.toLowerCase());
    });
  });

  describe("Full Entrypoint Authorization Hash", () => {
    it("should compute full message hash correctly", () => {
      const encoder = new Eip712Encoder();
      const call = Eip712Encoder.createFunctionCall(123n, "test(Field)", [
        456n,
      ]);
      const txNonce = 999n;

      // Build typed data
      const typedData = encoder.buildEntrypointTypedData5([call], txNonce);

      // Compute app domain hash
      const appDomainHash = Eip712Encoder.hashAppDomain(
        typedData.message.appDomain,
      );

      // Compute function calls array hash
      const callsArrayHash = Eip712Encoder.hashFunctionCallsArray(
        typedData.message.functionCalls,
      );

      // Compute entrypoint authorization hash (message hash / structHash)
      const messageHash = Eip712Encoder.hashEntrypointAuthorization5(
        typedData.message.appDomain,
        typedData.message.functionCalls,
        txNonce,
      );

      // Manual computation
      const manualMessageHash = keccak256(
        concat([
          NOIR_CONSTANTS.ENTRYPOINT_AUTHORIZATION_5_TYPE_HASH as `0x${string}`,
          appDomainHash,
          callsArrayHash,
          pad(toHex(txNonce), { size: 32 }),
        ]),
      );

      expect(messageHash.toLowerCase()).toBe(manualMessageHash.toLowerCase());
    });
  });

  describe("Final EIP-712 Payload", () => {
    it("should compute final payload correctly (0x1901 || domainSeparator || messageHash)", () => {
      const domainSeparator = NOIR_CONSTANTS.DOMAIN_SEPARATOR as `0x${string}`;
      const messageHash =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" as `0x${string}`;

      const payload = Eip712Encoder.computeEip712Payload(
        domainSeparator,
        messageHash,
      );

      // Manual computation
      const manualPayload = keccak256(
        concat(["0x1901", domainSeparator, messageHash]),
      );

      expect(payload.toLowerCase()).toBe(manualPayload.toLowerCase());
    });
  });
});
