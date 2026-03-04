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
} as const;

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
 * Waits for the counter value to be visible on page.
 */
export async function waitForCounter(page: Page): Promise<void> {
  const readBtn = page.getByRole("button", { name: /Read/i });
  await expect(readBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
}
