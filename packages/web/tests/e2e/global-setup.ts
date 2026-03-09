/**
 * Playwright Global Setup
 *
 * Deploys the Counter contract to the Aztec sandbox using the offchain deploy script,
 * then writes .env with the contract address so the Vite dev server picks it up.
 * This makes the full-flow e2e test independent of in-browser deploy.
 */

import { writeFileSync } from "fs";
import { execSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const AZTEC_NODE_URL = process.env.AZTEC_NODE_URL || "http://localhost:8080";

export default async function globalSetup() {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const webRoot = join(__dirname, "../..");
  const offchainRoot = join(webRoot, "../offchain");
  const envPath = join(webRoot, ".env");

  // Deploy Counter contract via the offchain deploy script
  console.log("[global-setup] Deploying Counter contract via offchain script...");
  const output = execSync(
    `AZTEC_NODE_URL=${AZTEC_NODE_URL} npx tsx scripts/deploy.ts`,
    { cwd: offchainRoot, encoding: "utf-8", timeout: 120_000 },
  );

  // Extract contract address from deploy script output
  const match = output.match(/VITE_CONTRACT_ADDRESS=(\S+)/);
  if (!match) {
    console.error("[global-setup] Deploy output:\n", output);
    throw new Error("Failed to extract contract address from deploy output");
  }
  const contractAddress = match[1];
  console.log(`[global-setup] Counter deployed at ${contractAddress}`);

  // Write .env with the deployed contract address
  const envContent = [
    `VITE_AZTEC_NODE_URL=${AZTEC_NODE_URL}`,
    `VITE_EIP712_CHAIN_ID=31337`,
    `VITE_CONTRACT_ADDRESS=${contractAddress}`,
  ].join("\n");
  writeFileSync(envPath, envContent + "\n");
  console.log("[global-setup] Wrote .env with contract address");
}
