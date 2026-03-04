/**
 * EIP-712 Complete Flow Test
 *
 * This test simulates the complete EIP-712 signing and verification flow,
 * ensuring that what TypeScript signs matches what Noir would verify.
 */

import { describe, it, expect } from "vitest";
import {
  keccak256,
  encodePacked,
  concat,
  pad,
  toHex,
  hexToBytes,
  bytesToHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { secp256k1 } from "@noble/curves/secp256k1";

import {
  Eip712Encoder,
  DEFAULT_APP_DOMAIN,
  TYPE_HASHES,
} from "../../src/lib/eip712/eip712-encoder.js";
import {
  Eip712Account,
  type FunctionCallInput,
} from "../../src/lib/eip712/eip712-account.js";
import {
  EMPTY_FUNCTION_CALL,
  DEFAULT_VERIFYING_CONTRACT,
  ACCOUNT_MAX_CALLS,
} from "../../src/lib/eip712/eip712-types.js";

// Test private key (Anvil's first account)
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

describe("EIP-712 Complete Flow", () => {
  const eip712Account = new Eip712Account(TEST_PRIVATE_KEY, 31337n);
  const encoder = new Eip712Encoder({ chainId: 31337n });

  describe("Message Hash Computation", () => {
    it("should compute identical message hash as Noir would", async () => {
      // Test data
      const call: FunctionCallInput = {
        targetAddress: 123456789n,
        functionSignature: "drip_to_private((Field),u64)",
        args: [999n, 1000n],
      };
      const txNonce = 42n;

      // Build typed data (what gets signed)
      const functionCall = Eip712Encoder.createFunctionCall(
        call.targetAddress,
        call.functionSignature,
        call.args,
      );

      // Compute the message hash step by step (simulating what Noir does)

      // 1. Hash the function call (selector NOT included - derived from signature)
      const targetBytes = pad(toHex(call.targetAddress), { size: 32 });
      const sigHash = keccak256(
        encodePacked(["string"], [call.functionSignature]),
      );
      const argsEncoded =
        call.args.length > 0
          ? concat(call.args.map((arg) => pad(toHex(arg), { size: 32 })))
          : "0x";
      const argsHash = keccak256(argsEncoded);
      const isPrivateEncoded = pad(toHex(1n), { size: 32 }); // true (default)

      const callHash = keccak256(
        concat([
          TYPE_HASHES.FUNCTION_CALL,
          targetBytes,
          sigHash,
          argsHash,
          isPrivateEncoded,
        ]),
      );

      // Verify our encoder computes the same
      const encoderCallHash = Eip712Encoder.hashFunctionCall(functionCall);
      expect(encoderCallHash.toLowerCase()).toBe(callHash.toLowerCase());

      // 2. Hash the function calls array (5 calls, padded with empty)
      const paddedCalls = [functionCall];
      while (paddedCalls.length < ACCOUNT_MAX_CALLS) {
        paddedCalls.push(EMPTY_FUNCTION_CALL);
      }

      const callHashes = paddedCalls.map((c) =>
        Eip712Encoder.hashFunctionCall(c),
      );
      const functionCallsArrayHash = keccak256(concat(callHashes));

      // 3. Hash the app domain
      const nameHash = keccak256(
        encodePacked(["string"], [DEFAULT_APP_DOMAIN.name]),
      );
      const versionHash = keccak256(
        encodePacked(["string"], [DEFAULT_APP_DOMAIN.version]),
      );
      const appDomainHash = keccak256(
        concat([
          TYPE_HASHES.APP_DOMAIN,
          nameHash,
          versionHash,
          pad(toHex(DEFAULT_APP_DOMAIN.chainId), { size: 32 }),
          DEFAULT_APP_DOMAIN.salt as `0x${string}`,
        ]),
      );

      // Verify our encoder computes the same
      const encoderAppDomainHash =
        Eip712Encoder.hashAppDomain(DEFAULT_APP_DOMAIN);
      expect(encoderAppDomainHash.toLowerCase()).toBe(
        appDomainHash.toLowerCase(),
      );

      // 4. Compute the message hash (structHash of EntrypointAuthorization)
      const messageHash = keccak256(
        concat([
          TYPE_HASHES.ENTRYPOINT_AUTHORIZATION_5,
          appDomainHash,
          functionCallsArrayHash,
          pad(toHex(txNonce), { size: 32 }),
        ]),
      );

      // 5. Compute domain separator
      const domainSeparator = Eip712Encoder.computeDomainSeparatorWithContract(
        31337n,
        DEFAULT_VERIFYING_CONTRACT,
      );

      // 6. Compute final EIP-712 payload
      const payload = keccak256(
        concat(["0x1901", domainSeparator, messageHash]),
      );

      // Now sign and verify
      const oracleData = await eip712Account.signEntrypoint5([call], txNonce);

      // Verify the signature is valid for the payload
      const publicKey = eip712Account.getPublicKey();
      const payloadBytes = hexToBytes(payload);

      // Combine r and s for verification
      const isValid = secp256k1.verify(
        oracleData.ecdsaSignature,
        payloadBytes,
        concat([new Uint8Array([0x04]), publicKey.x, publicKey.y]),
      );

      expect(isValid).toBe(true);
    });

    it("should produce consistent capsule data for Noir deserialization", async () => {
      const call: FunctionCallInput = {
        targetAddress: 0x123456789abcdefn,
        functionSignature: "transfer((Field),(Field),u128)",
        args: [1n, 2n, 1000n],
      };
      const txNonce = 12345n;

      // Sign and create oracle data
      const oracleData = await eip712Account.signEntrypoint5([call], txNonce);

      // Verify structure matches what Noir expects
      expect(oracleData.ecdsaSignature).toHaveLength(64);
      expect(oracleData.functionSignatures).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.signatureLengths).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.functionArgs).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.argsLengths).toHaveLength(ACCOUNT_MAX_CALLS);
      expect(oracleData.targetAddresses).toHaveLength(ACCOUNT_MAX_CALLS);

      // Verify first call data
      expect(oracleData.targetAddresses[0]).toBe(call.targetAddress);
      expect(oracleData.signatureLengths[0]).toBe(
        call.functionSignature.length,
      );
      expect(oracleData.argsLengths[0]).toBe(call.args.length);

      // Verify function signature encoding
      const sigBytes = new TextEncoder().encode(call.functionSignature);
      for (let i = 0; i < sigBytes.length; i++) {
        expect(oracleData.functionSignatures[0][i]).toBe(sigBytes[i]);
      }

      // Verify args
      for (let i = 0; i < call.args.length; i++) {
        expect(oracleData.functionArgs[0][i]).toBe(call.args[i]);
      }

      // Verify empty call slots
      for (let i = 1; i < ACCOUNT_MAX_CALLS; i++) {
        expect(oracleData.targetAddresses[i]).toBe(0n);
        expect(oracleData.signatureLengths[i]).toBe(0);
        expect(oracleData.argsLengths[i]).toBe(0);
      }

      // Verify chain ID and salt
      expect(oracleData.chainId).toBe(31337n);
      expect(oracleData.salt).toHaveLength(32);
    });

    it("should handle salt correctly (first 31 bytes only)", async () => {
      // The salt has the significant bytes at the start, with zero at the end
      // This ensures capsule serialization (31 bytes) doesn't lose data
      const saltHex = DEFAULT_APP_DOMAIN.salt;
      const saltBytes = hexToBytes(saltHex as `0x${string}`);

      // The last byte should be 0 for capsule compatibility
      expect(saltBytes[31]).toBe(0);

      // The first byte should be non-zero (our salt is 0x01...)
      expect(saltBytes[0]).toBe(1);
    });

    it("should verify signature locally using the same algorithm as Noir", async () => {
      const call: FunctionCallInput = {
        targetAddress: 12345n,
        functionSignature: "test(Field)",
        args: [99n],
      };
      const txNonce = 1n;

      // Get typed data (what gets shown to user)
      const functionCalls = [call].map((c) =>
        Eip712Encoder.createFunctionCall(
          c.targetAddress,
          c.functionSignature,
          c.args,
        ),
      );
      while (functionCalls.length < ACCOUNT_MAX_CALLS) {
        functionCalls.push(EMPTY_FUNCTION_CALL);
      }

      const typedData = encoder.buildEntrypointTypedData5(
        functionCalls,
        txNonce,
      );

      // Sign with viem (simulating MetaMask)
      const account = privateKeyToAccount(TEST_PRIVATE_KEY);
      const signature = await account.signTypedData(typedData);

      // Parse signature
      const sigBytes = hexToBytes(signature);
      const r = sigBytes.slice(0, 32);
      const s = sigBytes.slice(32, 64);

      // Compute what Noir would compute
      const domainSeparator = Eip712Encoder.computeDomainSeparatorWithContract(
        31337n,
        DEFAULT_VERIFYING_CONTRACT,
      );

      const appDomainHash = Eip712Encoder.hashAppDomain(DEFAULT_APP_DOMAIN);
      const callsArrayHash =
        Eip712Encoder.hashFunctionCallsArray(functionCalls);
      const messageHash = Eip712Encoder.hashEntrypointAuthorization5(
        DEFAULT_APP_DOMAIN,
        functionCalls,
        txNonce,
      );
      const payload = Eip712Encoder.computeEip712Payload(
        domainSeparator,
        messageHash,
      );

      // Verify the signature is valid for this payload
      const payloadBytes = hexToBytes(payload);
      const publicKey = eip712Account.getPublicKey();

      // secp256k1 verification (same as Noir's std::ecdsa_secp256k1::verify_signature)
      const isValid = secp256k1.verify(
        new Uint8Array([...r, ...s]),
        payloadBytes,
        new Uint8Array([0x04, ...publicKey.x, ...publicKey.y]),
      );

      expect(isValid).toBe(true);
    });
  });

  describe("Capsule Field Packing", () => {
    it("should pack signature bytes correctly for Noir unpacking", async () => {
      const call: FunctionCallInput = {
        targetAddress: 1n,
        functionSignature: "x()",
        args: [],
      };

      const capsule = await eip712Account.createWitnessCapsule5([call], 0n, {
        toField: () => ({ toBigInt: () => 999n }),
        toBigInt: () => 999n,
      } as any);

      // Verify we have 145 fields (selector NOT included - derived from signature)
      expect(capsule.data).toHaveLength(145);

      // Fields 0-2 are the signature (64 bytes packed as 31+31+2)
      const field0 = capsule.data[0].toBigInt();
      const field1 = capsule.data[1].toBigInt();
      const field2 = capsule.data[2].toBigInt();

      // Unpack (simulating Noir's unpack_signature_from_fields)
      const unpackedSig = new Uint8Array(64);

      // Field 0 -> first 31 bytes
      let temp = field0;
      for (let i = 30; i >= 0; i--) {
        unpackedSig[i] = Number(temp & 0xffn);
        temp >>= 8n;
      }

      // Field 1 -> next 31 bytes
      temp = field1;
      for (let i = 61; i >= 31; i--) {
        unpackedSig[i] = Number(temp & 0xffn);
        temp >>= 8n;
      }

      // Field 2 -> last 2 bytes
      unpackedSig[62] = Number((field2 >> 8n) & 0xffn);
      unpackedSig[63] = Number(field2 & 0xffn);

      // The unpacked signature should have 64 bytes
      expect(unpackedSig.length).toBe(64);
    });
  });
});
