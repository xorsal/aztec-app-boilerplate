/**
 * Playwright Global Setup
 *
 * Writes .env for the Vite dev server WITHOUT a contract address.
 * Tests deploy the Counter contract in-browser via the "Deploy Counter" button,
 * making them self-contained and independent of offchain scripts.
 */

import { writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const AZTEC_NODE_URL = process.env.AZTEC_NODE_URL || "http://localhost:8080";

export default async function globalSetup() {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const webRoot = join(__dirname, "../..");
  const envPath = join(webRoot, ".env");

  // Write .env without VITE_CONTRACT_ADDRESS so the app shows the
  // "Deploy Counter" button, letting each test deploy its own instance.
  const envContent = [
    `VITE_AZTEC_NODE_URL=${AZTEC_NODE_URL}`,
    `VITE_EIP712_CHAIN_ID=31337`,
  ].join("\n");
  writeFileSync(envPath, envContent + "\n");
  console.log("[global-setup] Wrote .env (no contract address — tests deploy in-browser)");
}
