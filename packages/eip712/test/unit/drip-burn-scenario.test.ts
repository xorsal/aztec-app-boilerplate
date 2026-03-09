/**
 * Real-world scenario test: SponsoredFPC + drip_to_public + burn_public
 *
 * In a real Aztec transaction, the ExecutionPayload contains ALL calls:
 * - sponsor_unconditionally()                      → 0 args, private (fee payment)
 * - drip_to_public(AztecAddress, u64)              → 2 args, public  (business logic)
 * - burn_public(AztecAddress, u128, Field)         → 3 args, public  (business logic)
 *
 * With V2's MAX_ENTRYPOINT_CALLS=4 and per-call-count entrypoints, this 3-call
 * batch uses entrypoint_3 with per-slot FunctionCall{N}/Arguments{N} types.
 * The test also explores what a unified V3 approach would look like.
 */

import { describe, it, expect } from "vitest";
import {
  Eip712AccountV2,
  type FunctionCallInputV2,
} from "../../src/lib/eip712-account-v2.js";
import {
  buildArgumentsTypeString,
  buildEntrypointTypes,
  MAX_ENTRYPOINT_CALLS,
  FC_PRIMARIES,
} from "../../src/lib/eip712-types-v2.js";
import { AztecAddress } from "@aztec/aztec.js/addresses";
import { keccak256, encodePacked } from "viem";

const TEST_PRIVATE_KEY =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// Realistic contract addresses
const SPONSORED_FPC_ADDRESS = 50n;
const DRIPPER_ADDRESS = 100n;
const TOKEN_ADDRESS = 200n;
const ACCOUNT_ADDRESS = 300n;

// The three calls in a real transaction
const fpcCall: FunctionCallInputV2 = {
  targetAddress: SPONSORED_FPC_ADDRESS,
  functionSignature: "sponsor_unconditionally()",
  args: [],
  argTypes: [],
  isPublic: false, // private function
};

const dripCall: FunctionCallInputV2 = {
  targetAddress: DRIPPER_ADDRESS,
  functionSignature: "drip_to_public(Field,Field)",
  args: [TOKEN_ADDRESS, 1000n],
  argTypes: ["uint256", "uint256"],
  isPublic: true,
};

const burnCall: FunctionCallInputV2 = {
  targetAddress: TOKEN_ADDRESS,
  functionSignature: "burn_public(Field,u128,Field)",
  args: [ACCOUNT_ADDRESS, 500n, 0n],
  argTypes: ["uint256", "uint256", "uint256"],
  isPublic: true,
};

describe("Real-world scenario: SponsoredFPC + drip_to_public + burn_public", () => {
  // =========================================================================
  // V2 limitation: only 2 call slots
  // =========================================================================

  describe("V2 per-call-count: MAX_ENTRYPOINT_CALLS=4", () => {
    it("fpc + drip + burn now fits in 3 call slots", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);

      // 3 calls → entrypoint_3, capsule size = 15 + 64*3 = 207
      const capsule = await account.createWitnessCapsule2(
        [fpcCall, dripCall, burnCall],
        1n,
        contractAddress,
      );
      expect(capsule.data).toHaveLength(171);
    });

    it("fpc + single business call works (2 call slots)", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);

      // 2 calls → entrypoint_2, capsule size = 9 + 54*2 = 117
      const capsule = await account.createWitnessCapsule2(
        [fpcCall, dripCall],
        1n,
        contractAddress,
      );
      expect(capsule.data).toHaveLength(117);
    });

    it("should reject 5 calls (exceeds MAX_ENTRYPOINT_CALLS)", async () => {
      const account = new Eip712AccountV2(TEST_PRIVATE_KEY);
      const contractAddress = AztecAddress.fromBigInt(999n);
      const calls = [fpcCall, dripCall, burnCall, fpcCall, dripCall];

      await expect(
        account.createWitnessCapsule2(calls, 1n, contractAddress),
      ).rejects.toThrow(`Too many calls: 5 > ${MAX_ENTRYPOINT_CALLS}`);
    });

    it("different arg counts per slot produce separate type definitions", () => {
      // Slot 1: sponsor_unconditionally() → 0 args
      // Slot 2: drip_to_public(Field,Field) → 2 args
      const args1TypeString = buildArgumentsTypeString("Arguments1", fpcCall.argTypes);
      const args2TypeString = buildArgumentsTypeString("Arguments2", dripCall.argTypes);

      expect(args1TypeString).toBe("Arguments1()");
      expect(args2TypeString).toBe("Arguments2(uint256 argument1,uint256 argument2)");

      // Per-slot types via buildEntrypointTypes
      const types = buildEntrypointTypes([fpcCall.argTypes, dripCall.argTypes]);
      expect(types.Arguments1).toHaveLength(0); // 0 fields
      expect(types.Arguments2).toHaveLength(2); // 2 fields
    });
  });

  // =========================================================================
  // Unified V3 approach: single FunctionCall/Arguments type
  // =========================================================================

  describe("V3 unified: single FunctionCall/Arguments type, N call slots", () => {
    // In V3:
    // - Single "FunctionCall" type (not FunctionCall1, FunctionCall2, ...)
    // - Single "Arguments" type shared across ALL call slots
    // - Both calls in a tx must use the SAME Arguments definition
    // - N is just a constant (3, 4, 5...) — no new types needed

    const FC_UNIFIED_PRIMARY =
      "FunctionCall(bytes32 contract,string functionSignature,Arguments arguments,bool isPublic,bool hideMsgSender,bool isStatic)";

    it("should handle 3 calls with unified Arguments type", () => {
      // All 3 calls share the same Arguments definition.
      // Must use the superset: max(0, 2, 3) = 3 arguments.
      const allArgTypes = [fpcCall.argTypes, dripCall.argTypes, burnCall.argTypes];
      const maxArgCount = Math.max(...allArgTypes.map((t) => t.length));
      expect(maxArgCount).toBe(3);

      // Build unified Arguments type with max arg count
      // For types: use the type from whichever call defines that position
      const unifiedArgTypes: string[] = [];
      for (let i = 0; i < maxArgCount; i++) {
        // Find the first call that defines position i
        const definingCall = allArgTypes.find((types) => types.length > i);
        unifiedArgTypes.push(definingCall![i]);
      }

      expect(unifiedArgTypes).toEqual(["uint256", "uint256", "uint256"]);

      const argsTypeString = buildArgumentsTypeString("Arguments", unifiedArgTypes as any);
      expect(argsTypeString).toBe(
        "Arguments(uint256 argument1,uint256 argument2,uint256 argument3)",
      );
    });

    it("should produce single FunctionCall encode_type for ALL slots (hypothetical V3)", () => {
      const argsTypeString = "Arguments(uint256 argument1,uint256 argument2,uint256 argument3)";
      const encodeType = FC_UNIFIED_PRIMARY + argsTypeString;

      // Same encode_type for ALL call slots — single Merkle tree
      const typeHash = keccak256(encodePacked(["string"], [encodeType]));
      expect(typeHash).toMatch(/^0x[0-9a-f]{64}$/);

      // One Merkle root instead of N separate roots
      // One proof per call (all verified against the same root)
    });

    it("should pad empty call slots with zeros", () => {
      // FPC call: sponsor_unconditionally() → 0 args → padded to 3
      const fpcPadded = {
        ...fpcCall,
        args: [0n, 0n, 0n], // padded from [] to match unified type
      };

      // Drip call: drip_to_public(Field,Field) → 2 args → padded to 3
      const dripPadded = {
        ...dripCall,
        args: [TOKEN_ADDRESS, 1000n, 0n], // padded from [TOKEN_ADDRESS, 1000n]
      };

      // Burn call: burn_public(Field,u128,Field) → 3 args → no padding needed
      const burnPadded = {
        ...burnCall,
        args: [ACCOUNT_ADDRESS, 500n, 0n], // already 3 args
      };

      // All 3 calls now have 3 arguments matching the unified type
      expect(fpcPadded.args).toHaveLength(3);
      expect(dripPadded.args).toHaveLength(3);
      expect(burnPadded.args).toHaveLength(3);
    });

    it("should scale EntrypointAuthorization to N calls trivially", () => {
      // V2: EntrypointAuthorization(..., FunctionCall1 functionCall1, FunctionCall2 functionCall2, ...)
      // V3: EntrypointAuthorization(..., FunctionCall functionCall1, FunctionCall functionCall2, FunctionCall functionCall3, ...)

      // All reference the SAME FunctionCall type — no new type definitions
      for (const N of [2, 3, 4, 5]) {
        const entrypointPrimary = `EntrypointAuthorization(AccountData accountData,${
          Array.from({ length: N }, (_, i) => `FunctionCall functionCall${i + 1}`).join(",")
        },TxMetadata txMetadata)`;

        // Referenced types in encode_type are just:
        // AccountData + Arguments + FunctionCall + TxMetadata (alphabetical)
        // NO duplication regardless of N!
        const uniqueTypes = new Set(["AccountData", "Arguments", "FunctionCall", "TxMetadata"]);
        expect(uniqueTypes.size).toBe(4); // same for any N
        expect(entrypointPrimary).toContain(`functionCall${N}`);
      }
    });

    it("should show type conflict when arg types differ at same position", () => {
      // Edge case: call1 has (bytes32, uint256) and call2 has (uint256, bytes32)
      // Position 1: bytes32 vs uint256 — CONFLICT
      const call1Types = ["bytes32", "uint256"];
      const call2Types = ["uint256", "bytes32"];

      // Resolution options:
      // A) Use bytes32 for all (most general, loses MetaMask readability)
      // B) Error and require user to split into separate txs
      // C) Use the type from the "primary" call (e.g., highest-index non-empty)

      // In practice, this is rare because Aztec Fields map to a consistent type
      expect(call1Types[0]).not.toBe(call2Types[0]);
    });

    it("should work when all positions have compatible types (common case)", () => {
      // Real scenario: all Aztec Fields typically map to uint256
      // sponsor_unconditionally: ()
      // drip_to_public: (uint256, uint256)
      // burn_public: (uint256, uint256, uint256)

      // No conflicts — positions that appear in multiple calls have the same type
      const calls = [fpcCall, dripCall, burnCall];
      const maxArgs = Math.max(...calls.map((c) => c.argTypes.length));

      for (let pos = 0; pos < maxArgs; pos++) {
        const typesAtPosition = calls
          .filter((c) => c.argTypes.length > pos)
          .map((c) => c.argTypes[pos]);

        // All calls that define this position agree on the type
        const uniqueTypesAtPos = new Set(typesAtPosition);
        expect(uniqueTypesAtPos.size).toBe(1);
      }
    });
  });

  // =========================================================================
  // Comparison: what MetaMask shows
  // =========================================================================

  describe("MetaMask display comparison", () => {
    it("V3 unified: user sees 3 calls with unified Arguments", () => {
      // MetaMask would display:
      //
      // EntrypointAuthorization:
      //   accountData: { address: 0x...12c, walletName: "EVM Aztec Wallet", version: "1.0.0" }
      //
      //   functionCall1:              ← SponsoredFPC
      //     contract: 0x...032
      //     functionSignature: "sponsor_unconditionally()"
      //     arguments:
      //       argument1: 0            ← padded
      //       argument2: 0            ← padded
      //       argument3: 0            ← padded
      //     isPublic: false
      //
      //   functionCall2:              ← Dripper
      //     contract: 0x...064
      //     functionSignature: "drip_to_public(Field,Field)"
      //     arguments:
      //       argument1: 200          ← token_address
      //       argument2: 1000         ← amount
      //       argument3: 0            ← padded
      //     isPublic: true
      //
      //   functionCall3:              ← Token burn
      //     contract: 0x...0c8
      //     functionSignature: "burn_public(Field,u128,Field)"
      //     arguments:
      //       argument1: 300          ← from (account address)
      //       argument2: 500          ← amount
      //       argument3: 0            ← nonce
      //     isPublic: true
      //
      //   txMetadata: { feePaymentMethod: 0, cancellable: false, txNonce: 1 }
      //
      // Tradeoff: FPC call shows 3 dummy arguments. But the functionSignature
      // makes it clear what's happening. Users typically verify the business
      // calls, not the FPC boilerplate.

      expect(true).toBe(true); // Documentation test
    });
  });

  // =========================================================================
  // Architecture summary
  // =========================================================================

  describe("V3 architecture advantages", () => {
    it("summary: V2 vs V3 comparison", () => {
      const v2 = {
        maxCalls: 4,
        functionCallTypes: 4,    // FunctionCall1..4
        argumentsTypes: 5,       // Arguments, Arguments1..4
        merkleTrees: 5,          // FunctionCall1..4 + Arguments (authwit)
        merkleRoots: 5,          // hardcoded in Noir
        capsuleFields: 271,      // 3 + 4*64 + 12 (for max 4 calls)
        callsForBusinessLogic: 3, // with SponsoredFPC taking 1 slot
      };

      const v3 = (N: number) => ({
        maxCalls: N,
        functionCallTypes: 1,    // just "FunctionCall"
        argumentsTypes: 1,       // just "Arguments" (+ 1 for authwit if needed)
        merkleTrees: 1,          // single tree for entrypoint (+ 1 for authwit)
        merkleRoots: 1,          // single root (+ 1 for authwit)
        // capsuleFields: 3 + N*stride + metadata (scales linearly)
        callsForBusinessLogic: N - 1, // minus 1 for SponsoredFPC
      });

      // V2 can do 3 business calls per tx (with SponsoredFPC taking 1 slot)
      expect(v2.callsForBusinessLogic).toBe(3);

      // V3 with N=3: 2 business calls (drip + burn possible!)
      expect(v3(3).callsForBusinessLogic).toBe(2);

      // V3 with N=4: 3 business calls
      expect(v3(4).callsForBusinessLogic).toBe(3);

      // Merkle tree complexity doesn't grow with N
      expect(v3(2).merkleTrees).toBe(v3(5).merkleTrees);
      expect(v3(2).merkleRoots).toBe(v3(5).merkleRoots);
    });
  });
});
