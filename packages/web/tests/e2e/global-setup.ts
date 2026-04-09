import { execSync } from "node:child_process";
import { writeFileSync, existsSync, unlinkSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default function globalSetup() {
  const rootDir = resolve(__dirname, "../../../..");
  const webDir = resolve(__dirname, "../..");
  const envPath = resolve(webDir, ".env");
  const nodeUrl = process.env.VITE_AZTEC_NODE_URL || "http://localhost:8080";

  if (!existsSync(resolve(rootDir, "package.json"))) {
    throw new Error(
      `[global-setup] rootDir does not contain package.json: ${rootDir}`,
    );
  }

  // Always remove stale .env so we get a fresh deploy
  if (existsSync(envPath)) {
    unlinkSync(envPath);
    console.log("[global-setup] Removed stale .env");
  }

  console.log("[global-setup] Deploying counter contract...");

  const output = execSync("yarn deploy", {
    cwd: rootDir,
    encoding: "utf-8",
    timeout: 300_000,
    env: { ...process.env, AZTEC_NODE_URL: nodeUrl },
  });

  const match = output.match(/CONTRACT_ADDRESS=(0x[a-fA-F0-9]+)/);
  if (!match) {
    console.error(output);
    throw new Error(
      "[global-setup] Failed to extract CONTRACT_ADDRESS from deploy output",
    );
  }

  const contractAddress = match[1];
  console.log(`[global-setup] Counter deployed at: ${contractAddress}`);

  const envContent = [
    `VITE_AZTEC_NODE_URL=${nodeUrl}`,
    `VITE_CONTRACT_ADDRESS=${contractAddress}`,
    "",
  ].join("\n");

  writeFileSync(envPath, envContent);
  console.log("[global-setup] Wrote .env for web package");
}
