/**
 * Playwright Fixture for @wonderland/walletless
 *
 * Bundles and injects walletless directly into the browser via addInitScript,
 * providing a simulated MetaMask/EVM wallet for E2E tests.
 */

import { test as base, type Page } from "@playwright/test";
import { ANVIL_ACCOUNTS } from "@wonderland/walletless";

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
