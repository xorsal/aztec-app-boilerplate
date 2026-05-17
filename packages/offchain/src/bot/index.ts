import "dotenv/config";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import {
  INITIAL_TEST_SECRET_KEYS,
  INITIAL_TEST_ACCOUNT_SALTS,
} from "@aztec/accounts/testing";
import { CounterContract } from "../../../contracts/artifacts/Counter.js";
import { createPoller } from "./poller.js";
import { handleCounterEvent } from "./handler.js";

const DEFAULT_POLL_INTERVAL_MS = 5000;

function parsePollIntervalMs(raw: string | undefined): number {
  if (raw === undefined) return DEFAULT_POLL_INTERVAL_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    console.error(
      `❌ Invalid POLL_INTERVAL_MS=${JSON.stringify(raw)}; expected a positive number`,
    );
    process.exit(1);
  }
  return parsed;
}

const AZTEC_NODE_URL = process.env.AZTEC_NODE_URL || "http://localhost:8080";
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const POLL_INTERVAL_MS = parsePollIntervalMs(process.env.POLL_INTERVAL_MS);

async function main() {
  if (!CONTRACT_ADDRESS) {
    console.error("❌ CONTRACT_ADDRESS env var is required");
    process.exit(1);
  }

  console.log("🤖 Starting Counter Bot");
  console.log(`   Node URL: ${AZTEC_NODE_URL}`);
  console.log(`   Contract: ${CONTRACT_ADDRESS}`);
  console.log(`   Poll interval: ${POLL_INTERVAL_MS}ms`);
  console.log("");

  // Connect to Aztec node
  const aztecNode = await createAztecNodeClient(AZTEC_NODE_URL, {});

  // Create wallet
  const wallet = await EmbeddedWallet.create(aztecNode, {
    pxeConfig: {
      dataDirectory: "pxe-bot",
      proverEnabled: false,
    },
  });

  // Register first test account
  const accountManager = await wallet.createSchnorrAccount(
    INITIAL_TEST_SECRET_KEYS[0],
    INITIAL_TEST_ACCOUNT_SALTS[0],
  );
  const botAccount = accountManager.address;

  // Connect to deployed contract
  const contractAddress = AztecAddress.fromString(CONTRACT_ADDRESS);
  const counter = await CounterContract.at(contractAddress, wallet);

  console.log(`✅ Connected to Counter contract at ${contractAddress}`);
  console.log(`   Bot account: ${botAccount}\n`);

  // Start polling
  const poller = createPoller(async () => {
    const { result: value } = await counter.methods
      .get_counter()
      .simulate({ from: botAccount });
    await handleCounterEvent(value);
  }, POLL_INTERVAL_MS);

  poller.start();

  // Graceful shutdown
  const shutdown = () => {
    console.log("\n🛑 Shutting down bot...");
    poller.stop();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("❌ Bot failed:", error);
  process.exit(1);
});
