import { test, expect } from "@playwright/test";

test("embedded wallet: read and increment counter", async ({ page }) => {
  // Capture browser errors for debugging
  page.on("pageerror", (err) => {
    console.log(`[browser:error] ${err.message}`);
  });

  // 1. Navigate and wait for app
  await page.goto("/");
  await expect(page.locator("h1")).toContainText("Aztec App");

  // 2. Connect embedded wallet
  const embeddedButton = page.getByRole("button", { name: "Embedded" });
  await expect(embeddedButton).toBeVisible();
  await embeddedButton.click();

  // 3. Wait for wallet connection (PXE bootstrap + account registration)
  //    The "Disconnect" button appears when connected — this is the definitive signal
  await expect(
    page.getByRole("button", { name: "Disconnect" }),
  ).toBeVisible({ timeout: 180_000 });

  // 4. Wait for counter card to appear
  const counterCard = page.getByTestId("counter-card");
  await expect(counterCard).toBeVisible({ timeout: 30_000 });

  // 5. Read counter
  const readButton = page.getByRole("button", { name: "Read" });
  await expect(readButton).toBeVisible();
  await readButton.click();

  // Wait for value to load (replaces "—" with a number)
  const counterValue = page.getByTestId("counter-value");
  await expect(counterValue).not.toHaveText("—", { timeout: 60_000 });
  await expect(counterValue).not.toHaveText("", { timeout: 5_000 });

  const initialValue = BigInt(
    (await counterValue.textContent())!.trim(),
  );
  console.log(`[test] Initial counter value: ${initialValue}`);

  // 6. Increment counter — use a stable locator that doesn't depend on button text
  const incrementButton = page.getByRole("button", { name: "Increment" });
  await expect(incrementButton).toBeEnabled();
  await incrementButton.click();

  // Wait for tx to complete — the button text changes to "Sending tx..." then back
  // Use getByRole with exact text for "Increment" to detect when tx is done
  await expect(
    page.getByRole("button", { name: "Increment" }),
  ).toBeVisible({ timeout: 300_000 });

  // 7. Verify counter increased (auto-re-fetched after increment)
  await expect(async () => {
    const text = (await counterValue.textContent())!.trim();
    const newValue = BigInt(text);
    expect(newValue).toBeGreaterThan(initialValue);
  }).toPass({ timeout: 30_000 });

  const finalValue = BigInt(
    (await counterValue.textContent())!.trim(),
  );
  console.log(`[test] Final counter value: ${finalValue}`);
  console.log(`[test] Counter increased by ${finalValue - initialValue}`);
});
