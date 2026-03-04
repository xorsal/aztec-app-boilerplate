/**
 * E2E Test: Counter with EIP-712 Signing
 *
 * Uses the walletless fixture for MetaMask simulation.
 * Requires Aztec sandbox and deployed Counter contract.
 */

import { test, expect } from "./fixtures/walletless";
import { connectWallet, waitForCounter, TIMEOUTS } from "./utils/test-helpers";

test.describe("Counter EIP-712 E2E", () => {
  test("should have walletless provider injected", async ({
    page,
    walletless,
  }) => {
    await page.goto("/");

    const hasWalletless = await page.evaluate(() => {
      return !!(window as unknown as { ethereum?: { isWalletless?: boolean } })
        .ethereum?.isWalletless;
    });
    expect(hasWalletless).toBe(true);

    const accounts = await page.evaluate(async () => {
      return (
        window as unknown as {
          ethereum: {
            request: (args: { method: string }) => Promise<string[]>;
          };
        }
      ).ethereum.request({ method: "eth_accounts" });
    });
    expect(accounts[0].toLowerCase()).toBe(
      walletless.account.address.toLowerCase(),
    );
  });

  test("should connect wallet via EIP-712 flow", async ({
    page,
    walletless,
  }) => {
    console.log("\n=== E2E: EIP-712 Wallet Connection ===");
    console.log("Test account:", walletless.account.address);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await connectWallet(page);

    // Verify we see the disconnect button (connection successful)
    const disconnectBtn = page.getByRole("button", { name: /Disconnect/i });
    await expect(disconnectBtn).toBeVisible({ timeout: TIMEOUTS.LONG });

    console.log("=== TEST PASSED ===\n");
  });

  test("should increment counter with EIP-712 signing", async ({
    page,
    walletless,
  }) => {
    console.log("\n=== E2E: Counter Increment via EIP-712 ===");

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Connect wallet
    await connectWallet(page);

    // Wait for counter UI
    await waitForCounter(page);

    // Read initial counter value
    const readBtn = page.getByRole("button", { name: /^Read$/i });
    await readBtn.click();
    await page.waitForTimeout(2000);

    // Click increment - this triggers EIP-712 signing via walletless
    const incrementBtn = page.getByRole("button", { name: /Increment/i });
    await expect(incrementBtn).toBeVisible();
    await incrementBtn.click();

    // Wait for transaction to complete (button text changes during tx)
    await expect(incrementBtn).not.toHaveText("Sending tx...", {
      timeout: TIMEOUTS.LONG,
    });

    console.log("Counter incremented successfully");
    console.log("=== TEST PASSED ===\n");
  });
});
