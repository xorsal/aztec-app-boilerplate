import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import {
  INITIAL_TEST_SECRET_KEYS,
  INITIAL_TEST_ACCOUNT_SALTS,
} from "@aztec/accounts/testing";
import { deployCounter } from "../src/utils.js";

const AZTEC_NODE_URL = process.env.AZTEC_NODE_URL || "http://localhost:8080";

async function main() {
  console.log("🚀 Deploying Counter contract to Aztec Sandbox");
  console.log("=".repeat(50));

  // Connect to Aztec node
  console.log(`\n📡 Connecting to Aztec node at ${AZTEC_NODE_URL}...`);
  const aztecNode = await createAztecNodeClient(AZTEC_NODE_URL, {});

  // Create wallet
  console.log("💼 Initializing EmbeddedWallet...");
  const wallet = await EmbeddedWallet.create(aztecNode, {
    pxeConfig: {
      dataDirectory: "pxe-deploy",
      proverEnabled: false,
    },
  });

  // Register the first test account as owner/deployer
  console.log("👤 Setting up deployer account (Test Account #1)...");
  const accountManager = await wallet.createSchnorrAccount(
    INITIAL_TEST_SECRET_KEYS[0],
    INITIAL_TEST_ACCOUNT_SALTS[0],
  );
  const ownerAddress = accountManager.address;
  console.log(`   Owner/Deployer: ${ownerAddress.toString()}`);

  // Deploy the Counter contract
  console.log("\n📝 Deploying Counter contract...");
  const contract = await deployCounter(wallet, ownerAddress);

  console.log("\n✅ Deployment successful!");
  console.log("=".repeat(50));
  console.log(`\nContract Address: ${contract.address.toString()}`);
  console.log(`Deployer Address: ${ownerAddress.toString()}`);

  console.log("\n📝 Set these in your .env files:");
  console.log("-".repeat(50));
  console.log(`CONTRACT_ADDRESS=${contract.address.toString()}`);
  console.log(`VITE_CONTRACT_ADDRESS=${contract.address.toString()}`);
  console.log(`VITE_AZTEC_NODE_URL=${AZTEC_NODE_URL}`);

  process.exit(0);
}

main().catch((error) => {
  console.error("❌ Deployment failed:");
  console.error(error);
  process.exit(1);
});
