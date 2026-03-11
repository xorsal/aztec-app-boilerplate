export const AZTEC_NODE_URL =
  import.meta.env.VITE_AZTEC_NODE_URL || "http://localhost:8080";

export const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ADDRESS || "";

export const APP_ID = import.meta.env.VITE_APP_ID || "aztec-app-boilerplate";
export const CHAIN_ID = Number(import.meta.env.VITE_CHAIN_ID || "31337");
export const CHAIN_VERSION = Number(import.meta.env.VITE_CHAIN_VERSION || "1");
