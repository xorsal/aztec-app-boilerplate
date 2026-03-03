import { startSandbox } from "./scripts/start-sandbox.js";

/**
 * Vitest global setup — starts the Aztec sandbox before all tests
 * and tears it down after.
 */
export async function setup() {
  console.log("\n🔧 Setting up Aztec testing environment\n");

  let sandboxManager: any;

  try {
    console.log("Starting Aztec sandbox...");
    sandboxManager = await startSandbox();
    console.log("");
  } catch (error: any) {
    console.error(`\n❌ Setup failed: ${error.message}`);
    process.exit(1);
  }

  // Return teardown function
  return async () => {
    console.log("\nCleaning up Aztec testing environment");

    try {
      if (sandboxManager) {
        await sandboxManager.stop();
        console.log("✅ Sandbox stopped successfully");
      }
    } catch (error: any) {
      console.error("⚠️  Error during cleanup:", error.message);
    }
  };
}
