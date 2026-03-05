/**
 * Shared E2E Test Helpers
 *
 * Common utilities for wallet connection and test assertions.
 */

import { expect, type Page } from "@playwright/test";

/** Timeout constants for E2E tests */
export const TIMEOUTS = {
  SHORT: 5000,
  DEFAULT: 30000,
  LONG: 60000,
  TX: 120000,
} as const;

/**
 * Selects the account version (V1 or V2) via the toggle buttons.
 * Must be called BEFORE connecting the wallet.
 */
export async function selectAccountVersion(
  page: Page,
  version: "v1" | "v2",
): Promise<void> {
  const versionBtn = page.getByRole("button", {
    name: version.toUpperCase(),
    exact: true,
  });
  await expect(versionBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
  await versionBtn.click();
}

/**
 * Clicks the Connect MetaMask button and waits for connection to complete.
 */
export async function connectWallet(page: Page): Promise<void> {
  const connectBtn = page.getByRole("button", { name: /Connect MetaMask/i });
  await expect(connectBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
  await connectBtn.click();

  // Wait for the Disconnect button to appear (indicates successful connection)
  const disconnectBtn = page.getByRole("button", { name: /Disconnect/i });
  await expect(disconnectBtn).toBeVisible({ timeout: TIMEOUTS.LONG });
}

/**
 * Waits for the counter buttons to become interactive (contract registered with PXE).
 */
export async function waitForCounter(page: Page): Promise<void> {
  const readBtn = page.getByRole("button", { name: /^Read$/i });
  await expect(readBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
  // Wait until the button is enabled (contract registration complete)
  await expect(readBtn).toBeEnabled({ timeout: TIMEOUTS.LONG });
}
