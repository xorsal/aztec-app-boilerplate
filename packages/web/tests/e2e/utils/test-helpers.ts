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

/**
 * Waits for the Dripper + Token contracts to be registered with PXE.
 * Listens for the "[dripper] Both contracts registered" console log
 * emitted by DripperDisplay after successful registration.
 *
 * To avoid missing early console events, pass a `consoleLogs` array
 * that is populated in beforeEach. If the message was already seen,
 * this returns immediately.
 */
export async function waitForDripperRegistration(
  page: Page,
  consoleLogs?: string[],
): Promise<void> {
  const marker = "[dripper] Both contracts registered";
  if (consoleLogs?.some((msg) => msg.includes(marker))) return;

  await page.waitForEvent("console", {
    predicate: (msg) => msg.text().includes(marker),
    timeout: TIMEOUTS.TX,
  });
}

/**
 * Deploys the Counter contract via the in-browser "Deploy Counter" button,
 * then waits for the contract to be registered and interactive.
 *
 * If the deploy button is visible (no contract address configured or stored),
 * clicks it and waits for deployment to complete. If the counter is already
 * deployed (Read/Increment buttons visible), this is a no-op.
 *
 * This makes tests work both:
 * - With global-setup (contract pre-deployed → deploy button not shown → skips)
 * - Without global-setup (no contract → deploy button shown → clicks it)
 */
export async function deployCounterViaUI(page: Page): Promise<void> {
  const deployBtn = page.getByRole("button", { name: /Deploy Counter/i });

  // If deploy button is visible, deploy; otherwise contract already exists
  if (await deployBtn.isVisible({ timeout: TIMEOUTS.SHORT }).catch(() => false)) {
    await deployBtn.click();
    // Wait for deploying state to finish (button text returns to normal or disappears)
    await expect(deployBtn).not.toHaveText("Deploying...", {
      timeout: TIMEOUTS.TX,
    });
  }

  // Now wait for contract registration to complete (Read button becomes enabled)
  await waitForCounter(page);
}
