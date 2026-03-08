/**
 * E2E Tests: Counter with EIP-712 Signing (V1 and V2)
 *
 * Uses the walletless fixture for MetaMask simulation.
 * Requires Aztec sandbox running. Counter contract is deployed in-browser.
 *
 * V1: Fixed uint256[] argument encoding, 5 call slots
 * V2: Per-argument EIP-712 types (bytes32/uint256/int256) with Merkle proofs, 2 call slots
 */

import { test, expect } from "./fixtures/walletless";
import {
  selectAccountVersion,
  connectWallet,
  deployCounterViaUI,
  TIMEOUTS,
} from "./utils/test-helpers";

for (const version of ["v1", "v2"] as const) {
  test.describe(`Counter EIP-712 ${version.toUpperCase()} E2E`, () => {
    test(`[${version}] should connect wallet via EIP-712 flow`, async ({
      page,
      walletless,
    }) => {
      console.log(`\n=== E2E: EIP-712 ${version.toUpperCase()} Wallet Connection ===`);
      console.log("Test account:", walletless.account.address);

      await page.goto("/");
      await page.waitForLoadState("networkidle");

      // Select account version before connecting
      await selectAccountVersion(page, version);
      await connectWallet(page);

      // Verify we see the disconnect button (connection successful)
      const disconnectBtn = page.getByRole("button", { name: /Disconnect/i });
      await expect(disconnectBtn).toBeVisible({ timeout: TIMEOUTS.LONG });

      // Verify the version label shows in the header
      await expect(page.getByText(`EIP-712 ${version.toUpperCase()}`)).toBeVisible();

      console.log("=== TEST PASSED ===\n");
    });

    test(`[${version}] should increment counter with EIP-712 signing`, async ({
      page,
      walletless,
    }) => {
      console.log(`\n=== E2E: Counter Increment via EIP-712 ${version.toUpperCase()} ===`);

      await page.goto("/");
      await page.waitForLoadState("networkidle");

      // Select account version and connect
      await selectAccountVersion(page, version);
      await connectWallet(page);

      // Deploy counter (or skip if already deployed) and wait for PXE registration
      await deployCounterViaUI(page);

      // Read initial counter value
      const readBtn = page.getByRole("button", { name: /^Read$/i });
      await readBtn.click();
      await page.waitForTimeout(2000);

      // Click increment - this triggers EIP-712 signing via walletless
      const incrementBtn = page.getByRole("button", { name: /Increment/i });
      await expect(incrementBtn).toBeVisible();
      await expect(incrementBtn).toBeEnabled();
      await incrementBtn.click();

      // Wait for transaction to complete (button text changes during tx)
      await expect(incrementBtn).not.toHaveText("Sending tx...", {
        timeout: TIMEOUTS.TX,
      });

      console.log(`Counter incremented successfully (${version.toUpperCase()})`);
      console.log("=== TEST PASSED ===\n");
    });
  });
}
