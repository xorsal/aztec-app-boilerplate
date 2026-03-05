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
    sponsoredFpcAddress,
    isConnecting,
    isConnected,
    error,
    connect,
    disconnect,
    registerContractArtifact,
  } = useWalletStore();

  return {
    wallet,
    address,
    evmAddress,
    walletClient,
    sponsoredFpcAddress,
    isConnecting,
    isConnected,
    error,
    connect,
    disconnect,
    registerContractArtifact,
  };
}
