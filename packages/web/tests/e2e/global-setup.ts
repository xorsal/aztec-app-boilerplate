import { execSync } from "node:child_process";
import {
  writeFileSync,
  readFileSync,
  renameSync,
  existsSync,
} from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { AztecAddress } from "@aztec/stdlib/aztec-address";

const __dirname = dirname(fileURLToPath(import.meta.url));

const DEFAULT_NODE_URL = "http://localhost:8080";

function parseEnvFile(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

async function isContractDeployed(
  nodeUrl: string,
  address: string,
): Promise<boolean> {
  try {
    const aztecNode = await createAztecNodeClient(nodeUrl, {});
    const instance = await aztecNode.getContract(
      AztecAddress.fromString(address),
    );
    return instance !== undefined;
  } catch (err) {
    console.warn(
      `[global-setup] Contract existence check failed: ${(err as Error).message}`,
    );
    return false;
  }
}

export default async function globalSetup() {
  const rootDir = resolve(__dirname, "../../../..");
  const webDir = resolve(__dirname, "../..");
  const envPath = resolve(webDir, ".env");

  // Precedence: AZTEC_NODE_URL > VITE_AZTEC_NODE_URL > default.
  const nodeUrl =
    process.env.AZTEC_NODE_URL ||
    process.env.VITE_AZTEC_NODE_URL ||
    DEFAULT_NODE_URL;

  if (!existsSync(resolve(rootDir, "package.json"))) {
    throw new Error(
      `[global-setup] rootDir does not contain package.json: ${rootDir}`,
    );
  }

  // Back up any existing developer .env so teardown can restore it.
  // We use a timestamped path and expose it via env so teardown picks it up.
  let backupPath: string | null = null;
  let existingEnv: Record<string, string> = {};
  if (existsSync(envPath)) {
    existingEnv = parseEnvFile(readFileSync(envPath, "utf-8"));
    backupPath = `${envPath}.e2e-backup-${Date.now()}`;
    renameSync(envPath, backupPath);
    process.env.E2E_ENV_BACKUP_PATH = backupPath;
    console.log(`[global-setup] Backed up existing .env to ${backupPath}`);
  } else {
    // Signal to teardown that there was no original .env to restore.
    delete process.env.E2E_ENV_BACKUP_PATH;
  }

  // Decide whether we can reuse a previously deployed contract.
  // Skip redeploy only if all of the following are true:
  //   - the backed-up .env had a VITE_AZTEC_NODE_URL that matches `nodeUrl`
  //   - it carries a VITE_CONTRACT_ADDRESS
  //   - the contract still exists on-chain at that node
  // In CI we always redeploy to avoid acting on stale cache.
  const cachedNodeUrl = existingEnv["VITE_AZTEC_NODE_URL"];
  const cachedContract = existingEnv["VITE_CONTRACT_ADDRESS"];
  const canConsiderCache =
    !process.env.CI &&
    cachedNodeUrl === nodeUrl &&
    !!cachedContract &&
    /^0x[a-fA-F0-9]+$/.test(cachedContract);

  let contractAddress: string | null = null;
  if (canConsiderCache) {
    console.log(
      `[global-setup] Found cached contract ${cachedContract} at ${nodeUrl}; verifying on-chain...`,
    );
    if (await isContractDeployed(nodeUrl, cachedContract!)) {
      contractAddress = cachedContract!;
      console.log("[global-setup] Cached contract verified, skipping deploy");
    } else {
      console.log(
        "[global-setup] Cached contract not found on-chain, redeploying",
      );
    }
  }

  if (!contractAddress) {
    console.log("[global-setup] Deploying counter contract...");
    const output = execSync("yarn deploy", {
      cwd: rootDir,
      encoding: "utf-8",
      timeout: 300_000,
      env: {
        ...process.env,
        // Pass both env vars so any caller (deploy script, Vite-style env
        // readers, etc.) sees a consistent node URL.
        AZTEC_NODE_URL: nodeUrl,
        VITE_AZTEC_NODE_URL: nodeUrl,
      },
    });

    const match = output.match(/CONTRACT_ADDRESS=(0x[a-fA-F0-9]+)/);
    if (!match) {
      console.error(output);
      throw new Error(
        "[global-setup] Failed to extract CONTRACT_ADDRESS from deploy output",
      );
    }

    contractAddress = match[1];
    console.log(`[global-setup] Counter deployed at: ${contractAddress}`);
  }

  const envContent = [
    `VITE_AZTEC_NODE_URL=${nodeUrl}`,
    `VITE_CONTRACT_ADDRESS=${contractAddress}`,
    "",
  ].join("\n");

  writeFileSync(envPath, envContent);
  console.log("[global-setup] Wrote .env for web package");

  // Note: when running locally with `reuseExistingServer: true`, an
  // already-running Vite dev server will NOT pick up the new .env. If you hit
  // stale config, restart `yarn dev` or run with CI=1 to force a fresh server.
  if (!process.env.CI) {
    console.log(
      "[global-setup] Note: if a Vite dev server is already running, restart it to pick up env changes",
    );
  }
}
