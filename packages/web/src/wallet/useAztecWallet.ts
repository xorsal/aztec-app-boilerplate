import { useWalletStore } from "./store";

/**
 * Lean hook for accessing the Aztec wallet state.
 * Wraps the Zustand store for convenient component use.
 */
export function useAztecWallet() {
  const { wallet, address, isConnecting, isConnected, error, connect, disconnect } =
    useWalletStore();

  return {
    wallet,
    address,
    isConnecting,
    isConnected,
    error,
    connect,
    disconnect,
  };
}
