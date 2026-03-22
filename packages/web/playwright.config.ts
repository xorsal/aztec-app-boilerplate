import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  globalSetup: "./tests/e2e/global-setup.ts",
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://localhost:3001",
    headless: !!(process.env.CI || process.env.HEADLESS),
  },
  expect: {
    timeout: 30_000,
  },
  timeout: 400_000,
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        screenshot: "only-on-failure",
        launchOptions: {
          args: ["--enable-features=SharedArrayBuffer"],
        },
      },
    },
  ],
  webServer: {
    command: "yarn dev --port 3001",
    url: "http://localhost:3001",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
