/**
 * EIP-712 V2 Noir Compatibility Tests
 *
 * Cross-verification that TypeScript EIP-712 V2 encoding produces hashes
 * matching what the Noir circuit computes. Covers type_hashes, encode_type
 * strings, hashStruct values, Merkle roots, and the domain separator.
 */

import { describe, it, expect } from "vitest";
import { keccak256, encodePacked, concat, pad, toHex } from "viem";

import {
  Eip712EncoderV2,
  ACCOUNT_DATA_TYPE_HASH,
  TX_METADATA_TYPE_HASH,
  AUTHWIT_APP_DOMAIN_TYPE_HASH,
  EIP712_DOMAIN_TYPE_HASH,
  DEFAULT_ACCOUNT_DATA,
  AZTEC_DOMAIN_V2,
} from "../../src/lib/eip712-encoder-v2.js";

import {
  type ArgumentType,
  FC_PRIMARIES,
  FC_AUTH_PRIMARY,
  DEFAULT_VERIFYING_CONTRACT_V2,
  buildArgumentsTypeString,
  buildEntrypointAuthPrimary,
} from "../../src/lib/eip712-types-v2.js";

import {
  getMerkleRoot,
  MERKLE_ROOT_FC_1,
  MERKLE_ROOT_FC_2,
  MERKLE_ROOT_FC_3,
  MERKLE_ROOT_FC_4,
  MERKLE_ROOT_FC_AUTH,
} from "../../src/lib/merkle-tree-data.js";

// Convenience aliases for per-slot FunctionCall primaries
const FC1_PRIMARY = FC_PRIMARIES[1];
const FC2_PRIMARY = FC_PRIMARIES[2];

// =============================================================================
// Noir hardcoded constants (ground truth from eip712_v2.nr / main.nr)
// =============================================================================

const NOIR_MERKLE_ROOTS = {
  MERKLE_ROOT_FC_1:
    "0x23807fde3749e9b5ddbc6c91886cc6e55280139ed5518a318fb21af017089c94",
  MERKLE_ROOT_FC_2:
    "0x1b95d5f26019d68281772cf97daae098abad03aff858c1790ec3082b717a0565",
  MERKLE_ROOT_FC_3:
    "0x02080475653ec163fc95413db7dc583f5b7e732d02cf9a6e00ffb8fe9117f4b4",
  MERKLE_ROOT_FC_4:
    "0x21f9fe446360ae84bb7119f92dcfb979bb8731016aa844f9ce71437bd5734d90",
  MERKLE_ROOT_FC_AUTH:
    "0x054a9fe2ce02ae6f96b01ea4962e3d41b2da0856e4027a2e2c53cf04c3271eda",
};

const NOIR_DOMAIN_SEPARATOR =
  "0x0c4d2d20583d2ee0c940ac2789fd85e2758be2b7546e627efa99bab898e5a141";

// =============================================================================
// Tests
// =============================================================================

describe("EIP-712 V2 Noir Compatibility", () => {
  // ---------------------------------------------------------------------------
  // 1. Type Hash Verification
  // ---------------------------------------------------------------------------
  describe("Type Hashes", () => {
    it("AccountData type hash matches manual keccak256", () => {
      const computed = keccak256(
        encodePacked(
          ["string"],
          ["AccountData(bytes32 address,string walletName,string version)"],
        ),
      );
      expect(ACCOUNT_DATA_TYPE_HASH.toLowerCase()).toBe(
        computed.toLowerCase(),
      );
    });

    it("TxMetadata type hash matches manual keccak256", () => {
      const computed = keccak256(
        encodePacked(
          ["string"],
          [
            "TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)",
          ],
        ),
      );
      expect(TX_METADATA_TYPE_HASH.toLowerCase()).toBe(computed.toLowerCase());
    });

    it("AuthwitAppDomain type hash matches manual keccak256", () => {
      const computed = keccak256(
        encodePacked(
          ["string"],
          ["AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)"],
        ),
      );
      expect(AUTHWIT_APP_DOMAIN_TYPE_HASH.toLowerCase()).toBe(
        computed.toLowerCase(),
      );
    });

    it("Arguments type hash for 0 args", () => {
      const typeString = buildArgumentsTypeString("Arguments1", []);
      expect(typeString).toBe("Arguments1()");
      const hash = keccak256(encodePacked(["string"], [typeString]));
      const computed = Eip712EncoderV2.computeArgumentsTypeHash(
        "Arguments1",
        [],
      );
      expect(computed.toLowerCase()).toBe(hash.toLowerCase());
    });

    it("Arguments type hash for 1 arg (bytes32)", () => {
      const argTypes: ArgumentType[] = ["bytes32"];
      const typeString = buildArgumentsTypeString("Arguments1", argTypes);
      expect(typeString).toBe("Arguments1(bytes32 argument1)");
      const hash = keccak256(encodePacked(["string"], [typeString]));
      const computed = Eip712EncoderV2.computeArgumentsTypeHash(
        "Arguments1",
        argTypes,
      );
      expect(computed.toLowerCase()).toBe(hash.toLowerCase());
    });

    it("Arguments type hash for mixed types (bytes32, uint256, int256)", () => {
      const argTypes: ArgumentType[] = ["bytes32", "uint256", "int256"];
      const typeString = buildArgumentsTypeString("Arguments2", argTypes);
      expect(typeString).toBe(
        "Arguments2(bytes32 argument1,uint256 argument2,int256 argument3)",
      );
      const hash = keccak256(encodePacked(["string"], [typeString]));
      const computed = Eip712EncoderV2.computeArgumentsTypeHash(
        "Arguments2",
        argTypes,
      );
      expect(computed.toLowerCase()).toBe(hash.toLowerCase());
    });

    it("FunctionCall type hash with specific Arguments definition", () => {
      const argTypes: ArgumentType[] = ["bytes32", "uint256"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      // FunctionCall1 encode_type = FC_PRIMARIES[1] + Arguments1(...)
      const encodeType = FC_PRIMARIES[1] + argsTypeString;
      const expected = keccak256(encodePacked(["string"], [encodeType]));
      const computed = Eip712EncoderV2.computeFunctionCallTypeHash(
        FC_PRIMARIES[1],
        argsTypeString,
      );
      expect(computed.toLowerCase()).toBe(expected.toLowerCase());
    });

    it("FunctionCall type hash with different Arguments definition", () => {
      const argTypes: ArgumentType[] = ["int256"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const encodeType = FC_PRIMARIES[1] + argsTypeString;
      const expected = keccak256(encodePacked(["string"], [encodeType]));
      const computed = Eip712EncoderV2.computeFunctionCallTypeHash(
        FC_PRIMARIES[1],
        argsTypeString,
      );
      expect(computed.toLowerCase()).toBe(expected.toLowerCase());
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Encode Type Construction
  // ---------------------------------------------------------------------------
  describe("Encode Type Construction", () => {
    it("buildEntrypointEncodeType has primary struct first, referenced types alphabetically sorted", () => {
      const args1Types: ArgumentType[] = ["bytes32", "uint256"];
      const args2Types: ArgumentType[] = ["int256"];

      const args1TypeString = buildArgumentsTypeString(
        "Arguments1",
        args1Types,
      );
      const args2TypeString = buildArgumentsTypeString(
        "Arguments2",
        args2Types,
      );

      const encodeType = Eip712EncoderV2.buildEntrypointEncodeType(
        args1TypeString,
        args2TypeString,
      );

      // Primary must come first
      const expectedPrimary = buildEntrypointAuthPrimary(2);
      expect(encodeType.startsWith(expectedPrimary)).toBe(true);

      // Extract referenced types (everything after primary)
      const afterPrimary = encodeType.slice(expectedPrimary.length);

      // Referenced types should appear in alphabetical order:
      // AccountData, Arguments1, Arguments2, FunctionCall1, FunctionCall2, TxMetadata
      const accountDataDef =
        "AccountData(bytes32 address,string walletName,string version)";
      const txMetadataDef =
        "TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)";

      const idxAccountData = afterPrimary.indexOf("AccountData(");
      const idxArgs1 = afterPrimary.indexOf("Arguments1(");
      const idxArgs2 = afterPrimary.indexOf("Arguments2(");
      const idxFC1 = afterPrimary.indexOf("FunctionCall1(");
      const idxFC2 = afterPrimary.indexOf("FunctionCall2(");
      const idxTxMeta = afterPrimary.indexOf("TxMetadata(");

      expect(idxAccountData).toBeLessThan(idxArgs1);
      expect(idxArgs1).toBeLessThan(idxArgs2);
      expect(idxArgs2).toBeLessThan(idxFC1);
      expect(idxFC1).toBeLessThan(idxFC2);
      expect(idxFC2).toBeLessThan(idxTxMeta);

      // Verify all referenced types are present
      expect(afterPrimary).toContain(accountDataDef);
      expect(afterPrimary).toContain(args1TypeString);
      expect(afterPrimary).toContain(args2TypeString);
      expect(afterPrimary).toContain(FC1_PRIMARY);
      expect(afterPrimary).toContain(FC2_PRIMARY);
      expect(afterPrimary).toContain(txMetadataDef);
    });

    it("buildAuthwitEncodeType has primary first, referenced types alphabetically sorted", () => {
      const argTypes: ArgumentType[] = ["uint256", "bytes32"];
      const argsTypeString = buildArgumentsTypeString("Arguments", argTypes);

      const encodeType =
        Eip712EncoderV2.buildAuthwitEncodeType(argsTypeString);

      // Primary must come first
      expect(encodeType.startsWith(FC_AUTH_PRIMARY)).toBe(true);

      const afterPrimary = encodeType.slice(FC_AUTH_PRIMARY.length);

      // Referenced types in alphabetical order: Arguments, AuthwitAppDomain
      const idxArgs = afterPrimary.indexOf("Arguments(");
      const idxAuthwit = afterPrimary.indexOf("AuthwitAppDomain(");

      expect(idxArgs).toBeLessThan(idxAuthwit);
    });

    it("buildFunctionCallEncodeType for FC1 concatenates correctly", () => {
      const argTypes: ArgumentType[] = ["bytes32"];
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const encodeType = Eip712EncoderV2.buildFunctionCallEncodeType(
        FC1_PRIMARY,
        argsTypeString,
      );
      // FC1_PRIMARY already includes "Arguments1 arguments" reference,
      // so encode_type = FC1_PRIMARY + Arguments1(...)
      expect(encodeType).toBe(FC1_PRIMARY + argsTypeString);
      expect(encodeType.startsWith(FC1_PRIMARY)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. hashStruct Computation
  // ---------------------------------------------------------------------------
  describe("hashStruct Computation", () => {
    it("hashStruct(AccountData) matches manual computation", () => {
      const accountData = {
        address:
          "0x00000000000000000000000000000000000000000000000000000000000000ab" as `0x${string}`,
        walletName: "EVM Aztec Wallet",
        version: "1.0.0",
      };

      const walletNameHash = keccak256(
        encodePacked(["string"], [accountData.walletName]),
      );
      const versionHash = keccak256(
        encodePacked(["string"], [accountData.version]),
      );

      const manual = keccak256(
        concat([
          ACCOUNT_DATA_TYPE_HASH,
          accountData.address,
          walletNameHash,
          versionHash,
        ]),
      );

      const computed = Eip712EncoderV2.hashAccountData(accountData);
      expect(computed.toLowerCase()).toBe(manual.toLowerCase());
    });

    it("hashStruct(TxMetadata) matches manual computation", () => {
      const txMetadata = {
        feePaymentMethod: 2,
        cancellable: true,
        txNonce: 42n,
      };

      const manual = keccak256(
        concat([
          TX_METADATA_TYPE_HASH,
          pad(toHex(txMetadata.feePaymentMethod), { size: 32 }),
          pad(toHex(1n), { size: 32 }), // cancellable = true
          pad(toHex(txMetadata.txNonce), { size: 32 }),
        ]),
      );

      const computed = Eip712EncoderV2.hashTxMetadata(txMetadata);
      expect(computed.toLowerCase()).toBe(manual.toLowerCase());
    });

    it("hashStruct(Arguments1) with specific types and values", () => {
      const argTypes: ArgumentType[] = ["bytes32", "uint256"];
      const argValues = [0xdeadbeefn, 1000n];

      const typeHash = Eip712EncoderV2.computeArgumentsTypeHash(
        "Arguments1",
        argTypes,
      );
      const manual = keccak256(
        concat([
          typeHash,
          pad(toHex(argValues[0]), { size: 32 }),
          pad(toHex(argValues[1]), { size: 32 }),
        ]),
      );

      const computed = Eip712EncoderV2.hashArguments(
        "Arguments1",
        argTypes,
        argValues,
      );
      expect(computed.toLowerCase()).toBe(manual.toLowerCase());
    });

    it("hashStruct(Arguments) with 0 args is keccak256(typeHash)", () => {
      const typeHash = Eip712EncoderV2.computeArgumentsTypeHash(
        "Arguments1",
        [],
      );
      const manual = keccak256(typeHash);
      const computed = Eip712EncoderV2.hashArguments("Arguments1", [], []);
      expect(computed.toLowerCase()).toBe(manual.toLowerCase());
    });

    it("hashStruct(FunctionCall1) end-to-end", () => {
      const contract =
        "0x0000000000000000000000000000000000000000000000000000000000000123" as `0x${string}`;
      const functionSignature = "transfer(Field,u128)";
      const argTypes: ArgumentType[] = ["bytes32", "uint256"];
      const argValues = [456n, 789n];
      const isPublic = false;
      const hideMsgSender = false;
      const isStatic = false;

      // Manual step-by-step
      const argsTypeString = buildArgumentsTypeString("Arguments1", argTypes);
      const fcEncodeType = FC1_PRIMARY + argsTypeString;
      const fcTypeHash = keccak256(encodePacked(["string"], [fcEncodeType]));

      const sigHash = keccak256(
        encodePacked(["string"], [functionSignature]),
      );
      const argsHash = Eip712EncoderV2.hashArguments(
        "Arguments1",
        argTypes,
        argValues,
      );

      const manual = keccak256(
        concat([
          fcTypeHash,
          contract,
          sigHash,
          argsHash,
          pad(toHex(0n), { size: 32 }), // isPublic = false
          pad(toHex(0n), { size: 32 }), // hideMsgSender = false
          pad(toHex(0n), { size: 32 }), // isStatic = false
        ]),
      );

      const computed = Eip712EncoderV2.hashFunctionCallV2(
        FC1_PRIMARY,
        "Arguments1",
        contract,
        functionSignature,
        argTypes,
        argValues,
        isPublic,
        hideMsgSender,
        isStatic,
      );
      expect(computed.toLowerCase()).toBe(manual.toLowerCase());
    });

    it("hashStruct(EntrypointAuthorization) end-to-end", () => {
      const accountData = {
        address:
          "0x0000000000000000000000000000000000000000000000000000000000000001" as `0x${string}`,
        walletName: "EVM Aztec Wallet",
        version: "1.0.0",
      };
      const txMetadata = {
        feePaymentMethod: 0,
        cancellable: false,
        txNonce: 99n,
      };

      const args1Types: ArgumentType[] = ["bytes32"];
      const args2Types: ArgumentType[] = [];

      const accountDataHash = Eip712EncoderV2.hashAccountData(accountData);
      const txMetadataHash = Eip712EncoderV2.hashTxMetadata(txMetadata);

      const fc1Hash = Eip712EncoderV2.hashFunctionCallV2(
        FC1_PRIMARY,
        "Arguments1",
        "0x0000000000000000000000000000000000000000000000000000000000000abc" as `0x${string}`,
        "test(Field)",
        args1Types,
        [555n],
        false,
        false,
        false,
      );

      const fc2Hash = Eip712EncoderV2.hashFunctionCallV2(
        FC2_PRIMARY,
        "Arguments2",
        "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`,
        "",
        args2Types,
        [],
        false,
        false,
        false,
      );

      // Manual entrypoint hash
      const entrypointTypeHash = Eip712EncoderV2.computeEntrypointTypeHash(
        [args1Types, args2Types],
      );
      const manual = keccak256(
        concat([
          entrypointTypeHash,
          accountDataHash,
          fc1Hash,
          fc2Hash,
          txMetadataHash,
        ]),
      );

      const computed = Eip712EncoderV2.hashEntrypointAuthorization(
        accountDataHash,
        [fc1Hash, fc2Hash],
        txMetadataHash,
        [args1Types, args2Types],
      );

      expect(computed.toLowerCase()).toBe(manual.toLowerCase());
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Merkle Root Consistency
  // ---------------------------------------------------------------------------
  describe("Merkle Root Consistency", () => {
    it("getMerkleRoot('FunctionCall1') matches Noir MERKLE_ROOT_FC_1", () => {
      const root = getMerkleRoot("FunctionCall1");
      expect(root.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_1.toLowerCase(),
      );
    });

    it("getMerkleRoot('FunctionCall2') matches Noir MERKLE_ROOT_FC_2", () => {
      const root = getMerkleRoot("FunctionCall2");
      expect(root.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_2.toLowerCase(),
      );
    });

    it("getMerkleRoot('FunctionCall3') matches Noir MERKLE_ROOT_FC_3", () => {
      const root = getMerkleRoot("FunctionCall3");
      expect(root.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_3.toLowerCase(),
      );
    });

    it("getMerkleRoot('FunctionCall4') matches Noir MERKLE_ROOT_FC_4", () => {
      const root = getMerkleRoot("FunctionCall4");
      expect(root.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_4.toLowerCase(),
      );
    });

    it("getMerkleRoot('Arguments') matches Noir MERKLE_ROOT_FC_AUTH", () => {
      const root = getMerkleRoot("Arguments");
      expect(root.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_AUTH.toLowerCase(),
      );
    });

    it("exported constants match getMerkleRoot", () => {
      expect(MERKLE_ROOT_FC_1.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_1.toLowerCase(),
      );
      expect(MERKLE_ROOT_FC_2.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_2.toLowerCase(),
      );
      expect(MERKLE_ROOT_FC_3.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_3.toLowerCase(),
      );
      expect(MERKLE_ROOT_FC_4.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_4.toLowerCase(),
      );
      expect(MERKLE_ROOT_FC_AUTH.toLowerCase()).toBe(
        NOIR_MERKLE_ROOTS.MERKLE_ROOT_FC_AUTH.toLowerCase(),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Domain Separator
  // ---------------------------------------------------------------------------
  describe("Domain Separator", () => {
    it("should match Noir hardcoded DOMAIN_SEPARATOR", () => {
      const separator = Eip712EncoderV2.computeDomainSeparator(
        31337n,
        DEFAULT_VERIFYING_CONTRACT_V2,
      );
      expect(separator.toLowerCase()).toBe(
        NOIR_DOMAIN_SEPARATOR.toLowerCase(),
      );
    });

    it("should be computed correctly step by step", () => {
      const domainTypeHash = keccak256(
        encodePacked(
          ["string"],
          [
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
          ],
        ),
      );
      expect(domainTypeHash.toLowerCase()).toBe(
        EIP712_DOMAIN_TYPE_HASH.toLowerCase(),
      );

      const nameHash = keccak256(
        encodePacked(["string"], [AZTEC_DOMAIN_V2.name]),
      );
      const versionHash = keccak256(
        encodePacked(["string"], [AZTEC_DOMAIN_V2.version]),
      );

      const separator = keccak256(
        concat([
          domainTypeHash,
          nameHash,
          versionHash,
          pad(toHex(31337n), { size: 32 }),
          pad(DEFAULT_VERIFYING_CONTRACT_V2, { size: 32 }),
        ]),
      );

      expect(separator.toLowerCase()).toBe(
        NOIR_DOMAIN_SEPARATOR.toLowerCase(),
      );
    });

    it("V2 domain uses name='Aztec' and version='1'", () => {
      expect(AZTEC_DOMAIN_V2.name).toBe("Aztec");
      expect(AZTEC_DOMAIN_V2.version).toBe("1");
    });
  });

  // ---------------------------------------------------------------------------
  // Final EIP-712 Payload
  // ---------------------------------------------------------------------------
  describe("Final EIP-712 Payload", () => {
    it("computeEip712Payload follows 0x1901 || domainSeparator || messageHash", () => {
      const domainSeparator = NOIR_DOMAIN_SEPARATOR as `0x${string}`;
      const messageHash =
        "0xaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd" as `0x${string}`;

      const payload = Eip712EncoderV2.computeEip712Payload(
        domainSeparator,
        messageHash,
      );

      const manual = keccak256(
        concat(["0x1901", domainSeparator, messageHash]),
      );

      expect(payload.toLowerCase()).toBe(manual.toLowerCase());
    });
  });
});
