/**
 * Playwright Global Setup: Deploy Counter Contract
 *
 * Runs the offchain deploy script to ensure a Counter contract exists
 * on the sandbox, then writes the address to the web package's .env.
 */

import { execSync } from "child_process";
import { writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const AZTEC_NODE_URL = process.env.AZTEC_NODE_URL || "http://localhost:8080";

export default async function globalSetup() {
  console.log("[global-setup] Deploying Counter contract via offchain script...");

  const __dirname = dirname(fileURLToPath(import.meta.url));
  const webRoot = join(__dirname, "../..");
  const monorepoRoot = join(webRoot, "../..");

  // Run the deploy script from the offchain package
  const output = execSync("npx tsx packages/offchain/scripts/deploy.ts", {
    cwd: monorepoRoot,
    env: { ...process.env, AZTEC_NODE_URL },
    encoding: "utf-8",
    timeout: 300_000,
  });

  console.log(output);

  // Extract the contract address from deploy output
  const match = output.match(/Contract Address:\s*(0x[a-fA-F0-9]+)/);
  if (!match) {
    throw new Error("[global-setup] Could not parse contract address from deploy output");
  }
  const contractAddress = match[1];

  // Write .env for the Vite dev server
  const envPath = join(webRoot, ".env");
  const envContent = [
    `VITE_CONTRACT_ADDRESS=${contractAddress}`,
    `VITE_AZTEC_NODE_URL=${AZTEC_NODE_URL}`,
    `VITE_EIP712_CHAIN_ID=31337`,
  ].join("\n");
  writeFileSync(envPath, envContent + "\n");
  console.log(`[global-setup] Wrote .env: VITE_CONTRACT_ADDRESS=${contractAddress}`);
}
