import { unlinkSync, existsSync, renameSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default function globalTeardown() {
  const envPath = resolve(__dirname, "../../.env");
  const backupPath = process.env.E2E_ENV_BACKUP_PATH;

  if (backupPath && existsSync(backupPath)) {
    // Restore the developer's original .env that setup moved aside.
    if (existsSync(envPath)) {
      unlinkSync(envPath);
    }
    renameSync(backupPath, envPath);
    console.log(
      `[global-teardown] Restored original .env from ${backupPath}`,
    );
    return;
  }

  // No backup => setup created the .env from scratch; remove it to leave the
  // working tree clean.
  if (existsSync(envPath)) {
    unlinkSync(envPath);
    console.log("[global-teardown] Cleaned up generated .env");
  }
}
