import { useWalletStore } from "./store";

/**
 * Hook for accessing the Aztec wallet state.
 * Wraps the Zustand store for convenient component use.
 */
export function useAztecWallet() {
  const {
    wallet,
    address,
    evmAddress,
    walletClient,
    signingDelegate,
    isConnecting,
    isConnected,
    error,
    connect,
    disconnect,
  } = useWalletStore();

  return {
    wallet,
    address,
    evmAddress,
    walletClient,
    signingDelegate,
    isConnecting,
    isConnected,
    error,
    connect,
    disconnect,
  };
}
