import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdtempSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

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

  const deployOutputFile = join(
    mkdtempSync(join(tmpdir(), "aztec-deploy-")),
    "deploy-output.json",
  );

  try {
    execSync("yarn deploy", {
      cwd: rootDir,
      encoding: "utf-8",
      timeout: 300_000,
      env: {
        ...process.env,
        AZTEC_NODE_URL: nodeUrl,
        DEPLOY_OUTPUT_FILE: deployOutputFile,
      },
    });

    if (!existsSync(deployOutputFile)) {
      throw new Error(
        `[global-setup] Deploy script did not write output file: ${deployOutputFile}`,
      );
    }

    const deployOutput = JSON.parse(readFileSync(deployOutputFile, "utf-8"));
    const contractAddress: string = deployOutput.contractAddress;

    if (!contractAddress) {
      throw new Error(
        "[global-setup] Deploy output missing contractAddress field",
      );
    }

    console.log(`[global-setup] Counter deployed at: ${contractAddress}`);

    const envContent = [
      `VITE_AZTEC_NODE_URL=${nodeUrl}`,
      `VITE_CONTRACT_ADDRESS=${contractAddress}`,
      "",
    ].join("\n");

    writeFileSync(envPath, envContent);
    console.log("[global-setup] Wrote .env for web package");
  } finally {
    if (existsSync(deployOutputFile)) {
      unlinkSync(deployOutputFile);
    }
  }
}
