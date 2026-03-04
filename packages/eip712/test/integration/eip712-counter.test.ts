/**
 * Integration Test: EIP-712 Account with Counter Contract
 *
 * Tests the complete EIP-712 clear signing flow:
 * 1. Deploy EIP-712 account contract
 * 2. Deploy Counter contract
 * 3. Increment counter via EIP-712 signed transaction
 * 4. Verify counter value increased
 *
 * Signing happens automatically via the Eip712SigningDelegate — no manual
 * prepareTx() calls needed. The entrypoint calls the delegate during
 * payload construction.
 *
 * This test requires the Aztec sandbox to be running on localhost:8080
 */

import { describe, it, expect, beforeAll } from "vitest";
import { createAztecNodeClient, type AztecNode } from "@aztec/aztec.js/node";
import type { ContractArtifact } from "@aztec/aztec.js/abi";
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

import { Eip712AccountContract } from "../../src/accounts/Eip712AccountContract.js";
import type { Eip712SigningDelegate } from "../../src/accounts/Eip712AuthWitnessProvider.js";
import {
  Eip712Account,
  createEip712Account,
  type FunctionCallInput,
} from "../../src/lib/eip712-account.js";
import {
  CounterContract,
  CounterContractArtifact,
} from "../../../contracts/artifacts/Counter.js";
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
 * Test signing delegate and auth witness provider for EIP-712.
 *
 * Implements Eip712SigningDelegate (creates capsules from FunctionCall[]).
 * Resolves function signatures automatically from registered contract artifacts.
 * The entrypoint calls createWitnessCapsule() automatically during payload construction.
 */
class TestEip712Provider implements Eip712SigningDelegate {
  private readonly artifactMap = new Map<string, ContractArtifact>();

  constructor(private eip712Signer: Eip712Account) {}

  /**
   * Register a contract artifact for automatic function signature resolution.
   */
  registerContractArtifact(address: AztecAddress, artifact: ContractArtifact): void {
    this.artifactMap.set(address.toString(), artifact);
  }

  /**
   * Creates an EIP-712 witness capsule for the given function calls.
   * Called by the entrypoint during payload construction.
   */
  async createWitnessCapsule(
    calls: FunctionCall[],
    txNonce: bigint,
    contractAddress: AztecAddress,
  ): Promise<Capsule> {
    const functionCalls = this.convertToFunctionCallInputs(calls);
    return this.eip712Signer.createWitnessCapsule5(
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

  private convertToFunctionCallInputs(
    calls: FunctionCall[],
  ): FunctionCallInput[] {
    return calls.map((call) => {
      const artifact = this.artifactMap.get(call.to.toString());
      if (artifact) {
        const func = findFunctionArtifact(artifact, call.name);
        if (func) {
          return {
            targetAddress: call.to.toField().toBigInt(),
            functionSignature: buildFunctionSignature(func),
            args: call.args.map((arg) => arg.toBigInt()),
            isPublic: call.type === FunctionType.PUBLIC,
          };
        }
      }

      console.warn(`[TestEip712Provider] No artifact for ${call.name} at ${call.to}`);
      return {
        targetAddress: call.to.toField().toBigInt(),
        functionSignature: `unknown_${call.name}`,
        args: call.args.map((arg) => arg.toBigInt()),
        isPublic: call.type === FunctionType.PUBLIC,
      };
    });
  }
}

describe("EIP-712 Counter Integration", () => {
  let aztecNode: AztecNode;
  let wallet: EmbeddedWallet;
  let eip712Signer: Eip712Account;
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

    // Create EIP-712 signing account
    eip712Signer = createEip712Account(
      TEST_PRIVATE_KEY,
      BigInt(nodeInfo.l1ChainId),
    );
  }, TEST_TIMEOUT);

  it("should connect to sandbox", async () => {
    const nodeInfo = await aztecNode.getNodeInfo();
    expect(nodeInfo).toBeDefined();
    expect(nodeInfo.l1ChainId).toBeGreaterThan(0);
  });

  it("should generate valid EIP-712 account keys", () => {
    const pubKey = eip712Signer.getPublicKey();
    expect(pubKey.x).toHaveLength(32);
    expect(pubKey.y).toHaveLength(32);

    const ethAddress = eip712Signer.getEthAddress();
    expect(ethAddress).toMatch(/^0x[0-9a-f]{40}$/i);
  });

  it(
    "should deploy EIP-712 account and increment counter",
    async () => {
      const pubKeyArrays = eip712Signer.getPublicKeyArrays();

      // Create the signing delegate — handles FunctionCall[] → capsule conversion.
      const testProvider = new TestEip712Provider(eip712Signer);

      // Register SponsoredFPC artifact for fee call signature resolution
      testProvider.registerContractArtifact(sponsoredFPCAddress, SponsoredFPCContractArtifact);

      // Create account contract with auth witness provider AND signing delegate
      const accountContract = new Eip712AccountContract(
        Buffer.from(pubKeyArrays.x),
        Buffer.from(pubKeyArrays.y),
        testProvider, // AuthWitnessProvider (createAuthWit → empty)
        testProvider, // Eip712SigningDelegate (createWitnessCapsule)
      );

      // Create account using AccountManager
      const secretKey = Fr.random();
      const accountManager = await AccountManager.create(
        wallet,
        secretKey,
        accountContract,
        Fr.random(),
      );

      // Register the account contract with the wallet's PXE
      const instance = accountManager.getInstance();
      const artifact = await accountManager.getAccountContract().getContractArtifact();
      await wallet.registerContract(instance, artifact, accountManager.getSecretKey());

      // Patch wallet to support EIP-712 account lookups.
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

      // Deploy the account using from: AztecAddress.ZERO (MultiCallEntrypoint).
      const deployMethod = await accountManager.getDeployMethod();
      await deployMethod.send({
        from: AztecAddress.ZERO,
        fee: { paymentMethod: sponsoredFeePaymentMethod },
        skipClassPublication: true,
        skipInstancePublication: true,
        wait: { timeout: 120 },
      });

      // Deploy Counter contract with EIP-712 account as owner
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

      // Increment counter via EIP-712 signed transaction.
      // This is the full E2E test: TS signing → capsule → Noir verification → execution.
      await counterContract.methods
        .increment()
        .send({
          from: accountAddress,
          fee: { paymentMethod: sponsoredFeePaymentMethod },
        });

      // Verify counter value increased
      const finalValue = await counterContract.methods
        .get_counter()
        .simulate({ from: AztecAddress.ZERO });
      expect(finalValue).toBe(1n);
    },
    TEST_TIMEOUT,
  );
});
