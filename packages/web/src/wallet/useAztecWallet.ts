import { useShallow } from "zustand/shallow";
import { useWalletStore } from "./store";

export function useAztecWallet() {
  return useWalletStore(useShallow((s) => ({
    wallet: s.wallet,
    address: s.address,
    walletType: s.walletType,
    isConnected: s.isConnected,
    isConnecting: s.isConnecting,
    error: s.error,

    // Discovery
    isDiscovering: s.isDiscovering,
    providers: s.providers,

    // Verification
    verificationEmojis: s.verificationEmojis,
    hasPendingVerification: s.pendingConnection !== null,

    // Actions
    startDiscovery: s.startDiscovery,
    cancelDiscovery: s.cancelDiscovery,
    connectExtension: s.connectExtension,
    confirmConnection: s.confirmConnection,
    cancelConnection: s.cancelConnection,
    connectEmbedded: s.connectEmbedded,
    disconnect: s.disconnect,
  })));
}
