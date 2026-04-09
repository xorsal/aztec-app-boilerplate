import { unlinkSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default function globalTeardown() {
  const envPath = resolve(__dirname, "../../.env");
  if (existsSync(envPath)) {
    unlinkSync(envPath);
    console.log("[global-teardown] Cleaned up .env");
  }
}
