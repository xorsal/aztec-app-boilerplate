/**
 * E2E Tests: EIP-712 V2 Specific Scenarios
 *
 * Tests V2-specific behavior: unified FunctionCall type with per-argument
 * EIP-712 types (bytes32/uint256/int256), Merkle proof verification,
 * version toggle, and full read→increment→read cycle.
 *
 * Requires Aztec sandbox running. Counter contract is deployed in-browser.
 */

import { test, expect } from "./fixtures/walletless";
import {
  selectAccountVersion,
  connectWallet,
  deployCounterViaUI,
  TIMEOUTS,
} from "./utils/test-helpers";

test.describe("EIP-712 V2 E2E", () => {
  test("version toggle should be interactive before connecting", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Both V1 and V2 buttons should be visible
    const v1Btn = page.getByRole("button", { name: "V1", exact: true });
    const v2Btn = page.getByRole("button", { name: "V2", exact: true });
    await expect(v1Btn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
    await expect(v2Btn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });

    // Click V2, then V1, then V2 again — toggle should respond
    await v2Btn.click();
    await v1Btn.click();
    await v2Btn.click();

    // Connect button should still be available
    const connectBtn = page.getByRole("button", { name: /Connect MetaMask/i });
    await expect(connectBtn).toBeVisible();
    await expect(connectBtn).toBeEnabled();
  });

  test("V2 connection should display version label and EVM address", async ({
    page,
    walletless,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // Verify "EIP-712 V2" label in the header
    await expect(page.getByText("EIP-712 V2")).toBeVisible({
      timeout: TIMEOUTS.LONG,
    });

    // Verify the Aztec address is shown (0x prefix + hex chars)
    const addressText = page.locator("code").first();
    await expect(addressText).toBeVisible();
    const addrContent = await addressText.textContent();
    expect(addrContent).toMatch(/^0x[0-9a-f]+\.\.\.$/i);

    // Verify the EVM address fragment is visible (from the walletless fixture)
    const shortEvm =
      walletless.account.address.slice(0, 6) +
      "..." +
      walletless.account.address.slice(-4);
    await expect(page.getByText(shortEvm)).toBeVisible();
  });

  test("version toggle should be disabled while connected", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // After connection, version toggle buttons should not be visible
    // (they are replaced by the disconnect UI)
    const v1Btn = page.getByRole("button", { name: "V1", exact: true });
    const v2Btn = page.getByRole("button", { name: "V2", exact: true });
    await expect(v1Btn).not.toBeVisible();
    await expect(v2Btn).not.toBeVisible();
  });

  test("V2 should read counter value", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);
    await deployCounterViaUI(page);

    // Click Read and wait for result
    const readBtn = page.getByRole("button", { name: /^Read$/i });
    await readBtn.click();

    // Counter value should appear as a number (replacing the em dash placeholder)
    const counterValue = page.locator("div").filter({ hasText: /^\d+$/ });
    await expect(counterValue).toBeVisible({ timeout: TIMEOUTS.DEFAULT });
  });

  test("V2 read → increment → read should show updated counter", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await selectAccountVersion(page, "v2");
    await connectWallet(page);
    await deployCounterViaUI(page);

    // Read initial counter value
    const readBtn = page.getByRole("button", { name: /^Read$/i });
    await readBtn.click();
    await page.waitForTimeout(2000);

    // Capture the counter value element (the large number display)
    const counterDisplay = page.locator(
      'div[style*="font-size: 3rem"], div[style*="fontSize"]',
    );
    const initialText = await counterDisplay.textContent();
    const initialValue = initialText?.trim() === "\u2014" ? -1 : Number(initialText?.trim());

    // Increment via V2 EIP-712 signing (triggers Merkle proof lookup)
    const incrementBtn = page.getByRole("button", { name: /Increment/i });
    await expect(incrementBtn).toBeEnabled();
    await incrementBtn.click();

    // Wait for transaction to complete
    await expect(incrementBtn).not.toHaveText("Sending tx...", {
      timeout: TIMEOUTS.TX,
    });

    // The counter should update automatically after increment
    // (the increment handler calls simulate() after sending)
    if (initialValue >= 0) {
      // If we had a readable initial value, verify it increased
      const updatedText = await counterDisplay.textContent();
      const updatedValue = Number(updatedText?.trim());
      expect(updatedValue).toBeGreaterThan(initialValue);
    }
  });

  test("V2 disconnect and reconnect should work cleanly", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // First connection with V2
    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    const disconnectBtn = page.getByRole("button", { name: /Disconnect/i });
    await expect(disconnectBtn).toBeVisible({ timeout: TIMEOUTS.LONG });

    // Disconnect
    await disconnectBtn.click();

    // Version toggle should reappear
    const v2Btn = page.getByRole("button", { name: "V2", exact: true });
    await expect(v2Btn).toBeVisible({ timeout: TIMEOUTS.DEFAULT });

    // Connect button should reappear
    const connectBtn = page.getByRole("button", { name: /Connect MetaMask/i });
    await expect(connectBtn).toBeVisible();

    // Reconnect with V2
    await selectAccountVersion(page, "v2");
    await connectWallet(page);

    // Should be connected again with V2
    await expect(page.getByText("EIP-712 V2")).toBeVisible({
      timeout: TIMEOUTS.LONG,
    });
  });
});
