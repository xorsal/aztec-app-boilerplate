import fs from "node:fs";
import path from "node:path";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import {
  INITIAL_TEST_SECRET_KEYS,
  INITIAL_TEST_ACCOUNT_SALTS,
} from "@aztec/accounts/testing";
import { DripperContract } from "@defi-wonderland/aztec-standards/dist/src/artifacts/Dripper.js";
import { TokenContract } from "@defi-wonderland/aztec-standards/dist/src/artifacts/Token.js";

const AZTEC_NODE_URL = process.env.AZTEC_NODE_URL || "http://localhost:8080";
const WEB_ENV_PATH = path.resolve(import.meta.dirname, "../../web/.env");

async function main() {
  console.log("Deploying Dripper + Token to Aztec Sandbox");
  console.log("=".repeat(50));

  console.log(`\nConnecting to Aztec node at ${AZTEC_NODE_URL}...`);
  const aztecNode = await createAztecNodeClient(AZTEC_NODE_URL, {});

  console.log("Initializing EmbeddedWallet...");
  const wallet = await EmbeddedWallet.create(aztecNode, {
    pxeConfig: {
      dataDirectory: "pxe-deploy-dripper",
      proverEnabled: false,
    },
  });

  console.log("Setting up deployer account (Test Account #1)...");
  const accountManager = await wallet.createSchnorrAccount(
    INITIAL_TEST_SECRET_KEYS[0],
    INITIAL_TEST_ACCOUNT_SALTS[0],
  );
  const deployerAddress = accountManager.address;
  console.log(`   Deployer: ${deployerAddress.toString()}`);

  // 1. Deploy Dripper (no constructor args)
  console.log("\nDeploying Dripper contract...");
  const dripper = await DripperContract.deploy(wallet).send({
    from: deployerAddress,
  });
  console.log(`   Dripper: ${dripper.address.toString()}`);

  // 2. Deploy Token with Dripper as minter
  console.log("Deploying Token contract (minter = Dripper)...");
  const token = await TokenContract.deployWithOpts(
    { wallet, method: "constructor_with_minter" as any },
    "Drip Token",
    "DRIP",
    18,
    dripper.address,
    AztecAddress.ZERO, // upgrade_authority
  ).send({ from: deployerAddress });
  console.log(`   Token:   ${token.address.toString()}`);

  console.log("\nDeployment successful!");
  console.log("=".repeat(50));

  // Write/update packages/web/.env
  const newVars: Record<string, string> = {
    VITE_DRIPPER_ADDRESS: dripper.address.toString(),
    VITE_TOKEN_ADDRESS: token.address.toString(),
    VITE_AZTEC_NODE_URL: AZTEC_NODE_URL,
  };

  let existing: Record<string, string> = {};
  if (fs.existsSync(WEB_ENV_PATH)) {
    for (const line of fs.readFileSync(WEB_ENV_PATH, "utf-8").split("\n")) {
      const match = line.match(/^([A-Z_]+)=(.*)$/);
      if (match) existing[match[1]] = match[2];
    }
  }

  const merged = { ...existing, ...newVars };
  const content = Object.entries(merged)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n") + "\n";
  fs.writeFileSync(WEB_ENV_PATH, content);

  console.log(`\nWrote ${WEB_ENV_PATH}:`);
  for (const [k, v] of Object.entries(newVars)) {
    console.log(`  ${k}=${v}`);
  }

  process.exit(0);
}

main().catch((error) => {
  console.error("Deployment failed:");
  console.error(error);
  process.exit(1);
});
