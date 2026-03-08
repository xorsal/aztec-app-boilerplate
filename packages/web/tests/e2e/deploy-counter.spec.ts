/**
 * E2E Tests: Counter Contract Deploy via In-Browser UI
 *
 * Validates the full lifecycle: deploy button visibility, in-browser
 * contract deployment, and subsequent read/increment interactions.
 *
 * These tests clear localStorage before each run to ensure no stale
 * contract address is cached. global-setup intentionally does NOT write
 * VITE_CONTRACT_ADDRESS, so the app always shows the "Deploy Counter"
 * button on first connect.
 *
 * Requires: Aztec sandbox running at localhost:8080
 */

import { test, expect } from "./fixtures/walletless";
import {
  selectAccountVersion,
  connectWallet,
  TIMEOUTS,
} from "./utils/test-helpers";

const LS_KEY = "aztec_counter_contract_address";

test.describe("Counter Deploy E2E", () => {
  test.beforeEach(async ({ page }) => {
    // Clear any stale contract address from localStorage before page loads.
    // This runs in the browser context before the app initializes.
    await page.addInitScript(() => {
      try {
        localStorage.removeItem("aztec_counter_contract_address");
      } catch {}
    });
  });

  test("should show 'Connect your wallet' message before connecting", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Before connecting, the counter card should prompt to connect
    await expect(page.getByText(/Connect your wallet/i)).toBeVisible({
      timeout: TIMEOUTS.DEFAULT,
    });

    // Deploy button should NOT be visible (requires wallet connection)
    const deployBtn = page.getByRole("button", { name: /Deploy Counter/i });
    await expect(deployBtn).not.toBeVisible();
  });

  test("should show deploy button after connecting wallet", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // With no VITE_CONTRACT_ADDRESS and localStorage cleared,
    // the deploy button should appear
    const deployBtn = page.getByRole("button", { name: /Deploy Counter/i });
    await expect(deployBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
    await expect(deployBtn).toBeEnabled();
  });

  test("should deploy counter and show counter interface", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // Click deploy
    const deployBtn = page.getByRole("button", { name: /Deploy Counter/i });
    await expect(deployBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
    await deployBtn.click();

    // Button should show "Deploying..." during deployment
    await expect(deployBtn).toHaveText("Deploying...", {
      timeout: TIMEOUTS.SHORT,
    });

    // Wait for deployment to finish (button disappears, counter UI appears)
    const readBtn = page.getByRole("button", { name: /^Read$/i });
    await expect(readBtn).toBeVisible({ timeout: TIMEOUTS.TX });
    await expect(readBtn).toBeEnabled({ timeout: TIMEOUTS.LONG });

    const incrementBtn = page.getByRole("button", { name: /Increment/i });
    await expect(incrementBtn).toBeVisible();
  });

  test("full cycle: deploy, read, increment, verify update", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // Deploy
    const deployBtn = page.getByRole("button", { name: /Deploy Counter/i });
    await expect(deployBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
    await deployBtn.click();

    // Wait for counter UI
    const readBtn = page.getByRole("button", { name: /^Read$/i });
    await expect(readBtn).toBeEnabled({ timeout: TIMEOUTS.TX });

    // Read initial value
    await readBtn.click();

    // Wait for the em dash to be replaced by a number
    const counterValue = page.locator("div").filter({ hasText: /^\d+$/ });
    await expect(counterValue.first()).toBeVisible({
      timeout: TIMEOUTS.DEFAULT,
    });
    const initialText = await counterValue.first().textContent();
    const initialValue = Number(initialText?.trim());

    // Increment
    const incrementBtn = page.getByRole("button", { name: /Increment/i });
    await expect(incrementBtn).toBeEnabled();
    await incrementBtn.click();

    // Wait for tx to complete
    await expect(incrementBtn).not.toHaveText("Sending tx...", {
      timeout: TIMEOUTS.TX,
    });

    // Counter should have updated (increment handler re-reads after send)
    const updatedText = await counterValue.first().textContent();
    const updatedValue = Number(updatedText?.trim());
    expect(updatedValue).toBeGreaterThan(initialValue);
  });

  test("deployed address should persist in localStorage", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // Deploy
    const deployBtn = page.getByRole("button", { name: /Deploy Counter/i });
    await expect(deployBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
    await deployBtn.click();

    // Wait for counter UI
    const readBtn = page.getByRole("button", { name: /^Read$/i });
    await expect(readBtn).toBeEnabled({ timeout: TIMEOUTS.TX });

    // Verify localStorage has the deployed address
    const storedAddr = await page.evaluate(
      (key) => localStorage.getItem(key),
      LS_KEY,
    );
    expect(storedAddr).toBeTruthy();
    expect(storedAddr).toMatch(/^0x[a-fA-F0-9]+$/);

    // Reload — stored address should skip the deploy step
    await page.reload();
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // Should go straight to counter UI (no deploy button)
    await expect(
      page.getByRole("button", { name: /Deploy Counter/i }),
    ).not.toBeVisible();
    await expect(readBtn).toBeVisible({ timeout: TIMEOUTS.LONG });
  });

  test("V1 account should also see deploy button", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v1");
    await connectWallet(page);

    const deployBtn = page.getByRole("button", { name: /Deploy Counter/i });
    await expect(deployBtn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
    await expect(deployBtn).toBeEnabled();
  });
});
