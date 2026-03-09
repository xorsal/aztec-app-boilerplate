/**
 * E2E Tests: Dripper – Drip to Private Flow
 *
 * Tests the full dripper flow with EIP-712 V2 signing:
 *   1. Connect wallet (V2 account via walletless fixture)
 *   2. Wait for account deployment
 *   3. Wait for Dripper + Token contract registration with PXE
 *   4. Read initial private balance (expect 0)
 *   5. Enter amount, click "Drip Private" (EIP-712 V2 signing with typed args)
 *   6. Verify private balance increased
 *
 * Requires:
 *   - Aztec sandbox running at localhost:8080
 *   - Dripper + Token contracts pre-deployed (global-setup handles this)
 */

import { test, expect } from "./fixtures/walletless";
import {
  selectAccountVersion,
  connectWallet,
  waitForDripperRegistration,
  TIMEOUTS,
} from "./utils/test-helpers";

test.describe("Dripper Drip-to-Private E2E", () => {
  /** Collect console logs early so we don't miss async events */
  let consoleLogs: string[];

  test.beforeEach(async ({ page }) => {
    consoleLogs = [];
    page.on("console", (msg) => {
      const text = msg.text();
      consoleLogs.push(text);
      if (
        text.includes("[wallet]") ||
        text.includes("[dripper]") ||
        text.includes("[SigningDelegate") ||
        msg.type() === "error"
      ) {
        console.log(`  [browser:${msg.type()}] ${text}`);
      }
    });
  });

  test("drip to private: connect, drip, verify balance increase", async ({
    page,
    walletless,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // ── 1. Select V2 and connect wallet ──
    await selectAccountVersion(page, "v2");
    await connectWallet(page);
    await expect(page.getByText("EIP-712 V2")).toBeVisible({
      timeout: TIMEOUTS.LONG,
    });

    // ── 2. Wait for account deployment ──
    // Check if the message was already captured
    if (!consoleLogs.some((m) => m.includes("[wallet] Account"))) {
      await page.waitForEvent("console", {
        predicate: (msg) => msg.text().includes("[wallet] Account"),
        timeout: TIMEOUTS.TX,
      });
    }

    // ── 3. Wait for Dripper + Token contract registration ──
    await waitForDripperRegistration(page, consoleLogs);

    // ── 4. Verify Dripper card is visible ──
    await expect(page.getByText("Private Balance:")).toBeVisible({
      timeout: TIMEOUTS.DEFAULT,
    });

    // ── 5. Read initial balance (click refresh, expect 0) ──
    const refreshBtn = page.getByRole("button", { name: "\u21BB" });
    await expect(refreshBtn).toBeEnabled({ timeout: TIMEOUTS.DEFAULT });
    await refreshBtn.click();

    // Wait for balance to settle (simulate call)
    const balanceValue = page.locator("text=Private Balance:").locator("..").locator("span").nth(1);
    await expect(balanceValue).not.toHaveText("...", {
      timeout: TIMEOUTS.DEFAULT,
    });
    const initialBalance = await balanceValue.textContent();
    expect(initialBalance?.trim()).toBe("0");

    // ── 6. Enter amount and click Drip Private ──
    const amountInput = page.locator("input[type='number']");
    await amountInput.clear();
    await amountInput.fill("100");

    const dripBtn = page.getByRole("button", { name: /Drip Private/i });
    await expect(dripBtn).toBeEnabled({ timeout: TIMEOUTS.DEFAULT });
    await dripBtn.click();

    // ── 7. Wait for transaction to complete ──
    // The button briefly shows "Signing & Sending..." then returns to "Drip Private".
    // With the walletless auto-signer this can happen too fast to catch the
    // intermediate state, so just wait for the success message directly.

    // ── 8. Verify success message ──
    await expect(page.getByText(/Dripped.*DRIP tokens privately/i)).toBeVisible({
      timeout: TIMEOUTS.DEFAULT,
    });

    // ── 9. Verify balance increased (auto-refreshed after drip) ──
    await expect(balanceValue).not.toHaveText("...", {
      timeout: TIMEOUTS.DEFAULT,
    });
    const updatedBalance = await balanceValue.textContent();
    expect(BigInt(updatedBalance?.trim() ?? "0")).toBeGreaterThan(0n);
  });
});
