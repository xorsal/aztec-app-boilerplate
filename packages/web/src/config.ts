export const AZTEC_NODE_URL =
  import.meta.env.VITE_AZTEC_NODE_URL || "http://localhost:8080";

export const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ADDRESS || "";

export const APP_ID = import.meta.env.VITE_APP_ID || "aztec-app-boilerplate";

function parseIntEnv(name: string, raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${name} must be an integer, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

export const CHAIN_ID = parseIntEnv("VITE_CHAIN_ID", import.meta.env.VITE_CHAIN_ID, 31337);
export const CHAIN_VERSION = parseIntEnv("VITE_CHAIN_VERSION", import.meta.env.VITE_CHAIN_VERSION, 1);
