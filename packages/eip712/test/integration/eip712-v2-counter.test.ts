/**
 * Integration Test: EIP-712 V2 Account with Counter Contract
 *
 * Tests the complete EIP-712 V2 clear signing flow with variable argument types:
 * 1. Deploy EIP-712 V2 account contract
 * 2. Deploy Counter contract
 * 3. Increment counter via EIP-712 V2 signed transaction (with Merkle proofs)
 * 4. Verify counter value increased
 * 5. Increment again and verify
 *
 * V2 differences from V1:
 * - Per-argument EIP-712 types (bytes32, uint256, int256) instead of fixed uint256[]
 * - Merkle tree whitelist for type validity
 * - Per-call-count entrypoints (entrypoint_1 through entrypoint_4) with per-slot types
 *
 * This test requires the Aztec sandbox to be running on localhost:8080
 */

import { describe, it, expect, beforeAll } from "vitest";
import { createAztecNodeClient, type AztecNode } from "@aztec/aztec.js/node";
import type { ContractArtifact, AbiType } from "@aztec/aztec.js/abi";
import { Fr } from "@aztec/aztec.js/fields";
import { AztecAddress } from "@aztec/aztec.js/addresses";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { getContractInstanceFromInstantiationParams } from "@aztec/aztec.js/contracts";
import { AuthWitness } from "@aztec/stdlib/auth-witness";
import type { FunctionCall } from "@aztec/stdlib/abi";
import { FunctionType } from "@aztec/stdlib/abi";
import type { Capsule } from "@aztec/stdlib/tx";
import { SPONSORED_FPC_SALT } from "@aztec/constants";
import { SponsoredFPCContractArtifact } from "@aztec/noir-contracts.js/SponsoredFPC";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { AccountManager } from "@aztec/aztec.js/wallet";
import type { Hex } from "viem";

import { Eip712AccountContractV2 } from "../../src/accounts/Eip712AccountContractV2.js";
import type { Eip712SigningDelegateV2 } from "../../src/accounts/Eip712AuthWitnessProviderV2.js";
import {
  Eip712AccountV2,
  createEip712AccountV2,
  type FunctionCallInputV2,
} from "../../src/lib/eip712-account-v2.js";
import type { ArgumentType } from "../../src/lib/eip712-types-v2.js";
import {
  CounterContract,
  CounterContractArtifact,
} from "../../../contracts/artifacts/Counter.js";
import { Eip712AccountV2ContractArtifact } from "../../src/artifacts.js";
import {
  buildFunctionSignature,
  findFunctionArtifact,
} from "../../src/utils/eip712-helpers.js";

// Test configuration
const PXE_URL = process.env.PXE_URL || "http://localhost:8080";
const TEST_TIMEOUT = 600_000; // 10 minutes for sandbox operations

// Use Anvil's first account private key for deterministic testing
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

/**
 * Infer an EIP-712 ArgumentType from a Noir ABI type.
 *
 * Field → bytes32 (addresses, hashes displayed as hex)
 * Unsigned integers → uint256
 * Signed integers → int256
 * Everything else → bytes32 (safe default)
 */
function noirTypeToArgumentType(abiType: AbiType): ArgumentType {
  if (typeof abiType === "string") {
    return "bytes32";
  }

  switch (abiType.kind) {
    case "field":
      return "bytes32";
    case "integer":
      return abiType.sign === "unsigned" ? "uint256" : "int256";
    case "boolean":
      return "uint256";
    default:
      return "bytes32";
  }
}

/**
 * Test signing delegate for EIP-712 V2.
 *
 * Implements Eip712SigningDelegateV2 (creates capsules with Merkle proofs from FunctionCall[]).
 * Resolves function signatures and per-argument types automatically from registered contract artifacts.
 * The entrypoint calls createWitnessCapsuleV2() automatically during payload construction.
 */
class TestEip712ProviderV2 implements Eip712SigningDelegateV2 {
  private readonly artifactMap = new Map<string, ContractArtifact>();

  constructor(private eip712Signer: Eip712AccountV2) {}

  /**
   * Register a contract artifact for automatic function signature and type resolution.
   */
  registerContractArtifact(address: AztecAddress, artifact: ContractArtifact): void {
    this.artifactMap.set(address.toString(), artifact);
  }

  /**
   * Creates a V2 EIP-712 witness capsule for the given function calls.
   * Called by the entrypoint during payload construction.
   */
  async createWitnessCapsuleV2(
    calls: FunctionCall[],
    txNonce: bigint,
    contractAddress: AztecAddress,
  ): Promise<Capsule> {
    const functionCalls = this.convertToFunctionCallInputsV2(calls);
    return this.eip712Signer.createWitnessCapsule2(
      functionCalls,
      txNonce,
      contractAddress,
    );
  }

  /**
   * Create an auth witness. Returns empty — signature is via capsule.
   */
  async createAuthWit(messageHash: Fr): Promise<AuthWitness> {
    return new AuthWitness(messageHash, []);
  }

  private convertToFunctionCallInputsV2(
    calls: FunctionCall[],
  ): FunctionCallInputV2[] {
    return calls.map((call) => {
      const artifact = this.artifactMap.get(call.to.toString());
      if (artifact) {
        const func = findFunctionArtifact(artifact, call.name);
        if (func) {
          // Infer per-argument EIP-712 types from the Noir ABI
          const argTypes: ArgumentType[] = func.parameters.map((param) =>
            noirTypeToArgumentType(param.type),
          );

          return {
            targetAddress: call.to.toField().toBigInt(),
            functionSignature: buildFunctionSignature(func),
            args: call.args.map((arg) => arg.toBigInt()),
            argTypes,
            isPublic: call.type === FunctionType.PUBLIC,
          };
        }
      }

      console.warn(`[TestEip712ProviderV2] No artifact for ${call.name} at ${call.to}`);
      return {
        targetAddress: call.to.toField().toBigInt(),
        functionSignature: `unknown_${call.name}`,
        args: call.args.map((arg) => arg.toBigInt()),
        argTypes: [] as ArgumentType[],
        isPublic: call.type === FunctionType.PUBLIC,
      };
    });
  }
}

describe("EIP-712 V2 Counter Integration", () => {
  let aztecNode: AztecNode;
  let wallet: EmbeddedWallet;
  let eip712Signer: Eip712AccountV2;
  let counterContract: CounterContract;
  let sponsoredFeePaymentMethod: SponsoredFeePaymentMethod;
  let sponsoredFPCAddress: AztecAddress;
  let accountAddress: AztecAddress;

  beforeAll(async () => {
    // Connect to Aztec Node
    aztecNode = createAztecNodeClient(PXE_URL);
    const nodeInfo = await aztecNode.getNodeInfo();

    // Create EmbeddedWallet (creates PXE internally)
    wallet = await EmbeddedWallet.create(aztecNode, {
      pxeConfig: { proverEnabled: false },
    });

    // Register SponsoredFPC contract for fee payment
    const sponsoredFPCInstance =
      await getContractInstanceFromInstantiationParams(
        SponsoredFPCContractArtifact,
        { salt: new Fr(SPONSORED_FPC_SALT) },
      );
    await wallet.registerContract(
      sponsoredFPCInstance,
      SponsoredFPCContractArtifact,
    );
    sponsoredFPCAddress = sponsoredFPCInstance.address;
    sponsoredFeePaymentMethod = new SponsoredFeePaymentMethod(
      sponsoredFPCAddress,
    );

    // Create EIP-712 V2 signing account
    eip712Signer = createEip712AccountV2(
      TEST_PRIVATE_KEY,
      BigInt(nodeInfo.l1ChainId),
    );
  }, TEST_TIMEOUT);

  it("should connect to sandbox", async () => {
    const nodeInfo = await aztecNode.getNodeInfo();
    expect(nodeInfo).toBeDefined();
    expect(nodeInfo.l1ChainId).toBeGreaterThan(0);
  });

  it("should generate valid EIP-712 V2 account keys", () => {
    const pubKey = eip712Signer.getPublicKey();
    expect(pubKey.x).toHaveLength(32);
    expect(pubKey.y).toHaveLength(32);

    const ethAddress = eip712Signer.getEthAddress();
    expect(ethAddress).toMatch(/^0x[0-9a-f]{40}$/i);
  });

  it(
    "should deploy EIP-712 V2 account and increment counter twice",
    async () => {
      const pubKeyArrays = eip712Signer.getPublicKeyArrays();

      // Create the V2 signing delegate — handles FunctionCall[] → capsule with Merkle proofs.
      const testProvider = new TestEip712ProviderV2(eip712Signer);

      // Register SponsoredFPC artifact for fee call signature resolution
      testProvider.registerContractArtifact(sponsoredFPCAddress, SponsoredFPCContractArtifact);

      // Create V2 account contract with auth witness provider AND signing delegate
      const accountContract = new Eip712AccountContractV2(
        Buffer.from(pubKeyArrays.x),
        Buffer.from(pubKeyArrays.y),
        testProvider, // AuthWitnessProvider (createAuthWit → empty)
        testProvider, // Eip712SigningDelegateV2 (createWitnessCapsuleV2)
      );

      // Create account using AccountManager
      const secretKey = Fr.random();
      const accountManager = await AccountManager.create(
        wallet,
        secretKey,
        accountContract,
        Fr.random(),
      );

      // Register the V2 account contract with the wallet's PXE
      const instance = accountManager.getInstance();
      const artifact = await accountManager.getAccountContract().getContractArtifact();
      await wallet.registerContract(instance, artifact, accountManager.getSecretKey());

      // Register V2 account artifact for signature resolution
      testProvider.registerContractArtifact(accountManager.address, Eip712AccountV2ContractArtifact);

      // Patch wallet to support EIP-712 V2 account lookups.
      // EmbeddedWallet only supports built-in account types in getAccountFromAddress(),
      // so we override it so send({ from: accountAddress }) finds our custom Account.
      const eip712AccountObj = await accountManager.getAccount();
      const origGetAccountFromAddress = (wallet as any).getAccountFromAddress.bind(wallet);
      (wallet as any).getAccountFromAddress = async (address: AztecAddress) => {
        if (address.equals(accountManager.address)) {
          return eip712AccountObj;
        }
        return origGetAccountFromAddress(address);
      };

      // Get the address before deployment
      accountAddress = accountManager.address;

      // Deploy the V2 account using from: AztecAddress.ZERO (MultiCallEntrypoint).
      const deployMethod = await accountManager.getDeployMethod();
      await deployMethod.send({
        from: AztecAddress.ZERO,
        fee: { paymentMethod: sponsoredFeePaymentMethod },
        skipClassPublication: true,
        skipInstancePublication: true,
        wait: { timeout: 120 },
      });

      // Deploy Counter contract with EIP-712 V2 account as owner
      const counterDeploy = await CounterContract.deployWithOpts(
        { wallet },
        accountAddress, // owner
      ).send({
        from: AztecAddress.ZERO,
        fee: { paymentMethod: sponsoredFeePaymentMethod },
      });

      const counterAddress = counterDeploy.address;
      counterContract = CounterContract.at(counterAddress, wallet);

      // Register Counter artifact for signature resolution
      testProvider.registerContractArtifact(counterAddress, CounterContractArtifact);

      // Verify initial counter value is 0
      const initialValue = await counterContract.methods
        .get_counter()
        .simulate({ from: AztecAddress.ZERO });
      expect(initialValue).toBe(0n);

      // First increment via EIP-712 V2 signed transaction.
      // Full E2E: TS type building → capsule with Merkle proof → Noir verification → execution.
      await counterContract.methods
        .increment()
        .send({
          from: accountAddress,
          fee: { paymentMethod: sponsoredFeePaymentMethod },
        });

      // Verify counter value is 1
      const afterFirst = await counterContract.methods
        .get_counter()
        .simulate({ from: AztecAddress.ZERO });
      expect(afterFirst).toBe(1n);

      // Second increment to verify repeat transactions work
      await counterContract.methods
        .increment()
        .send({
          from: accountAddress,
          fee: { paymentMethod: sponsoredFeePaymentMethod },
        });

      // Verify counter value is 2
      const afterSecond = await counterContract.methods
        .get_counter()
        .simulate({ from: AztecAddress.ZERO });
      expect(afterSecond).toBe(2n);
    },
    TEST_TIMEOUT,
  );
});
