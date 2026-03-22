import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default function globalSetup() {
  const rootDir = resolve(__dirname, "../../../..");
  const webDir = resolve(__dirname, "../..");
  const envPath = resolve(webDir, ".env");
  const nodeUrl = process.env.VITE_AZTEC_NODE_URL || "http://localhost:8080";

  // Skip deployment if .env already has a contract address
  if (existsSync(envPath)) {
    const existing = readFileSync(envPath, "utf-8");
    if (existing.includes("VITE_CONTRACT_ADDRESS=0x")) {
      console.log("[global-setup] .env already has contract address, skipping deploy");
      return;
    }
  }

  console.log("[global-setup] Deploying counter contract...");

  const output = execSync("yarn deploy", {
    cwd: rootDir,
    encoding: "utf-8",
    timeout: 300_000,
    env: { ...process.env, AZTEC_NODE_URL: nodeUrl },
  });

  console.log(output);

  // Extract contract address from deploy output
  const match = output.match(/CONTRACT_ADDRESS=(0x[a-fA-F0-9]+)/);
  if (!match) {
    throw new Error(
      "[global-setup] Failed to extract CONTRACT_ADDRESS from deploy output",
    );
  }

  const contractAddress = match[1];
  console.log(`[global-setup] Counter deployed at: ${contractAddress}`);

  // Write .env for the Vite dev server
  const envContent = [
    `VITE_AZTEC_NODE_URL=${nodeUrl}`,
    `VITE_CONTRACT_ADDRESS=${contractAddress}`,
    "",
  ].join("\n");

  writeFileSync(envPath, envContent);
  console.log("[global-setup] Wrote .env for web package");
}
