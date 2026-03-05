import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  globalSetup: "./tests/e2e/global-setup.ts",
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  workers: process.env.PLAYWRIGHT_NUM_WORKERS
    ? Number(process.env.PLAYWRIGHT_NUM_WORKERS)
    : 1,
  reporter: "list",
  use: {
    baseURL: "http://localhost:5173",
    headless: !!(process.env.CI || process.env.HEADLESS),
    launchOptions: {
      devtools: !process.env.CI,
    },
  },
  expect: {
    timeout: 20_000,
  },
  timeout: 400_000,
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  webServer: {
    command: "yarn dev --port 5173",
    url: "http://localhost:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
