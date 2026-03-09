/**
 * Playwright Fixture for @wonderland/walletless
 *
 * Bundles and injects walletless directly into the browser via addInitScript,
 * providing a simulated MetaMask/EVM wallet for E2E tests.
 *
 * NOTE: We inline the Anvil accounts here instead of importing from
 * @wonderland/walletless to avoid transitive dependency resolution issues
 * (walletless → viem → ox subpath export mismatch). The createE2EProvider
 * is bundled separately via esbuild which handles its own resolution.
 */

import { test as base, type Page } from "@playwright/test";

/**
 * Anvil's default test accounts, deterministically generated from:
 * "test test test test test test test test test test test junk"
 */
const ANVIL_ACCOUNTS = [
  {
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  },
  {
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    privateKey: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  },
  {
    address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    privateKey: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  },
  {
    address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    privateKey: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  },
  {
    address: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    privateKey: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  },
  {
    address: "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    privateKey: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  },
  {
    address: "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
    privateKey: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
  },
  {
    address: "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
    privateKey: "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
  },
  {
    address: "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
    privateKey: "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
  },
  {
    address: "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
    privateKey: "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
  },
] as const;

export interface WalletlessFixture {
  /** Current test account */
  account: (typeof ANVIL_ACCOUNTS)[0];
  /** All available Anvil accounts */
  accounts: typeof ANVIL_ACCOUNTS;
}

export interface WalletlessOptions {
  /** Enable debug logging */
  debug?: boolean;
  /** Initial account index (0-9), defaults to 0 */
  accountIndex?: number;
  /** Custom RPC URL, defaults to http://127.0.0.1:8545 */
  rpcUrl?: string;
  /** Chain ID, defaults to 31337 (Anvil) */
  chainId?: number;
}

let bundleCache: string | null = null;

async function getWalletlessBundle(): Promise<string> {
  if (bundleCache) return bundleCache;

  const { build } = await import("esbuild");
  const { join } = await import("path");

  // walletless's viem (2.43.5) needs ox@0.11.1, but yarn hoisted a stale
  // ox@0.8.1 into viem/node_modules. We add walletless/node_modules to the
  // search path so esbuild finds the correct ox@0.11.1 first.
  // Additionally, viem has its own nested node_modules/ox@0.8.1 that esbuild
  // prefers, so we alias "ox" to the correct version in walletless/node_modules.
  const { resolve: resolvePath, dirname } = await import("path");
  const { fileURLToPath: toPath } = await import("url");
  // Compute absolute paths from this fixture file location, not process.cwd()
  const fixtureDir = dirname(toPath(import.meta.url));
  const repoRoot = resolvePath(fixtureDir, "../../../../..");
  const walletlessNodeModules = join(
    repoRoot,
    "node_modules/@wonderland/walletless/node_modules",
  );
  const correctOxEsm = resolvePath(walletlessNodeModules, "ox/_esm");
  const oxRoot = resolvePath(walletlessNodeModules, "ox");
  const { readFileSync, existsSync } = await import("fs");
  const oxExports: Record<string, any> = JSON.parse(
    readFileSync(resolvePath(oxRoot, "package.json"), "utf-8"),
  ).exports ?? {};

  const result = await build({
    stdin: {
      contents: `export { createE2EProvider } from '@wonderland/walletless';`,
      resolveDir: process.cwd(),
      loader: "ts",
    },
    bundle: true,
    format: "iife",
    globalName: "Walletless",
    platform: "browser",
    target: "es2020",
    write: false,
    minify: true,
    nodePaths: [walletlessNodeModules],
    plugins: [
      {
        name: "resolve-ox",
        setup(pluginBuild) {
          // Force all "ox" and "ox/*" imports to the correct ox@0.11.1
          // that lives in walletless/node_modules, bypassing the stale
          // ox@0.8.1 nested inside viem/node_modules.
          // We read the exports map to resolve correctly: standard modules
          // go to _esm/core/{name}.js, extensions to _esm/{name}/index.js.
          pluginBuild.onResolve({ filter: /^ox(\/|$)/ }, (args) => {
            if (args.path === "ox") {
              return { path: resolvePath(correctOxEsm, "index.js") };
            }
            // Look up "./subpath" in the exports map
            const exportKey = "./" + args.path.slice(3); // "ox/erc8010" → "./erc8010"
            const entry = oxExports[exportKey];
            if (entry?.import) {
              return { path: resolvePath(oxRoot, entry.import) };
            }
            // Fallback: try _esm/core/{name}.js then _esm/{name}/index.js
            const subpath = args.path.slice(3);
            const coreFile = resolvePath(correctOxEsm, "core", subpath + ".js");
            if (existsSync(coreFile)) {
              return { path: coreFile };
            }
            return { path: resolvePath(correctOxEsm, subpath, "index.js") };
          });
        },
      },
    ],
  });

  const bundle = result.outputFiles?.[0]?.text ?? "";
  bundleCache = bundle + "\nwindow.Walletless = Walletless;";
  return bundleCache;
}

async function injectWalletless(
  page: Page,
  options: {
    chainId: number;
    rpcUrl: string;
    privateKey: string;
    debug: boolean;
  },
): Promise<void> {
  const { chainId, rpcUrl, privateKey, debug } = options;

  const bundle = await getWalletlessBundle();
  await page.addInitScript(bundle);

  await page.addInitScript(
    ({ chainId, rpcUrl, privateKey, debug }) => {
      try {
        const anvil = {
          id: chainId,
          name: "Anvil",
          nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
          rpcUrls: { default: { http: [rpcUrl] } },
        };

        const provider = (window as any).Walletless.createE2EProvider({
          rpcUrls: { [chainId]: rpcUrl },
          chains: [anvil],
          account: privateKey,
          debug,
        });

        (provider as any).isWalletless = true;
        (provider as any).isMetaMask = true;

        (window as any).ethereum = provider;
        if (debug) console.log("[walletless] Provider injected");
      } catch (e) {
        console.error("[walletless] Failed to inject provider:", e);
      }
    },
    { chainId, rpcUrl, privateKey, debug },
  );
}

export const test = base.extend<{
  walletless: WalletlessFixture;
  walletlessOptions: WalletlessOptions;
}>({
  walletlessOptions: [{}, { option: true }],

  walletless: async ({ page, context, walletlessOptions }, use) => {
    const {
      debug = false,
      accountIndex = 0,
      rpcUrl = "http://127.0.0.1:8545",
      chainId = 31337,
    } = walletlessOptions;

    await context.clearCookies();

    const privateKey = ANVIL_ACCOUNTS[accountIndex].privateKey;
    await injectWalletless(page, { chainId, rpcUrl, privateKey, debug });

    if (debug) {
      page.on("console", (msg) => {
        if (msg.text().includes("Walletless")) {
          console.log(`[browser] ${msg.text()}`);
        }
      });
    }

    await use({
      account: ANVIL_ACCOUNTS[accountIndex],
      accounts: ANVIL_ACCOUNTS,
    });
  },
});

export { expect } from "@playwright/test";
export { ANVIL_ACCOUNTS };
export type AnvilAccount = (typeof ANVIL_ACCOUNTS)[number];
