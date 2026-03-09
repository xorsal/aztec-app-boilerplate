export const AZTEC_NODE_URL =
  import.meta.env.VITE_AZTEC_NODE_URL || "http://localhost:8080";

export const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ADDRESS || "";

export const DRIPPER_ADDRESS = import.meta.env.VITE_DRIPPER_ADDRESS || "";

export const TOKEN_ADDRESS = import.meta.env.VITE_TOKEN_ADDRESS || "";

/** Chain ID for EIP-712 signing (default: Anvil local chain) */
export const EIP712_CHAIN_ID = BigInt(
  import.meta.env.VITE_EIP712_CHAIN_ID || "31337",
);
