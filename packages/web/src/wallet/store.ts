import { create } from "zustand";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { Fr } from "@aztec/aztec.js/fields";
import {
  INITIAL_TEST_SECRET_KEYS,
  INITIAL_TEST_ACCOUNT_SALTS,
} from "@aztec/accounts/testing";
import { WalletManager } from "@aztec/wallet-sdk/manager";
import type {
  WalletProvider,
  PendingConnection,
  DiscoverySession,
} from "@aztec/wallet-sdk/manager";
import { hashToEmoji } from "@aztec/wallet-sdk/crypto";
import type { Wallet } from "@aztec/aztec.js/wallet";
import { AZTEC_NODE_URL, APP_ID, CHAIN_ID, CHAIN_VERSION } from "../config";

type WalletType = "embedded" | "extension";

interface WalletState {
  // Connection
  wallet: Wallet | null;
  address: AztecAddress | null;
  walletType: WalletType | null;
  isConnected: boolean;
  isConnecting: boolean;
  error: string | null;

  // Discovery
  isDiscovering: boolean;
  providers: WalletProvider[];

  // Verification (extension only)
  pendingConnection: PendingConnection | null;
  verificationEmojis: string | null;

  // Internal refs (not rendered)
  _discoverySession: DiscoverySession | null;
  _disconnectUnsub: (() => void) | null;
  _provider: WalletProvider | null;

  // Actions
  startDiscovery: () => void;
  cancelDiscovery: () => void;
  connectExtension: (provider: WalletProvider) => Promise<void>;
  confirmConnection: () => Promise<void>;
  cancelConnection: () => void;
  connectEmbedded: () => Promise<void>;
  disconnect: () => void;
}

const initialState = {
  wallet: null,
  address: null,
  walletType: null,
  isConnected: false,
  isConnecting: false,
  error: null,
  isDiscovering: false,
  providers: [],
  pendingConnection: null,
  verificationEmojis: null,
  _discoverySession: null,
  _disconnectUnsub: null,
  _provider: null,
};

export const useWalletStore = create<WalletState>((set, get) => ({
  ...initialState,

  startDiscovery: () => {
    const state = get();
    if (state.isDiscovering || state.isConnected) return;

    set({ isDiscovering: true, providers: [], error: null });

    const chainInfo = {
      chainId: new Fr(CHAIN_ID),
      version: new Fr(CHAIN_VERSION),
    };

    const discovery = WalletManager.configure({
      extensions: { enabled: true },
    }).getAvailableWallets({
      chainInfo,
      appId: APP_ID,
      timeout: 60000,
      onWalletDiscovered: (provider: WalletProvider) => {
        set((s) => ({ providers: [...s.providers, provider] }));
      },
    });

    set({ _discoverySession: discovery });

    discovery.done.then(() => {
      // Only clear discovering if we haven't moved to connecting
      if (get()._discoverySession === discovery) {
        set({ isDiscovering: false });
      }
    });
  },

  cancelDiscovery: () => {
    const { _discoverySession } = get();
    _discoverySession?.cancel();
    set({
      isDiscovering: false,
      providers: [],
      _discoverySession: null,
    });
  },

  connectExtension: async (provider: WalletProvider) => {
    set({ isConnecting: true, error: null, _provider: provider });

    try {
      const pending = await provider.establishSecureChannel(APP_ID);
      const emojis = hashToEmoji(pending.verificationHash);

      set({
        pendingConnection: pending,
        verificationEmojis: emojis,
        isDiscovering: false,
      });
    } catch (error: any) {
      set({
        error: error.message || "Key exchange failed",
        isConnecting: false,
      });
    }
  },

  confirmConnection: async () => {
    const { pendingConnection, _provider } = get();
    if (!pendingConnection) return;

    try {
      const wallet = await pendingConnection.confirm();
      const accounts = await wallet.getAccounts();

      if (accounts.length === 0) {
        throw new Error("No accounts available in connected wallet");
      }

      const address = accounts[0].item;

      // Listen for disconnects via the provider
      const unsub = _provider?.onDisconnect(() => {
        get().disconnect();
      }) ?? null;

      set({
        wallet,
        address,
        walletType: "extension",
        isConnected: true,
        isConnecting: false,
        pendingConnection: null,
        verificationEmojis: null,
        providers: [],
        _discoverySession: null,
        _disconnectUnsub: unsub,
      });
    } catch (error: any) {
      set({
        error: error.message || "Failed to confirm connection",
        isConnecting: false,
        pendingConnection: null,
        verificationEmojis: null,
      });
    }
  },

  cancelConnection: () => {
    const { pendingConnection } = get();
    pendingConnection?.cancel();
    set({
      pendingConnection: null,
      verificationEmojis: null,
      isConnecting: false,
      _provider: null,
    });
  },

  connectEmbedded: async () => {
    if (get().isConnecting || get().isConnected) return;

    set({ isConnecting: true, error: null, isDiscovering: false, providers: [] });

    try {
      const aztecNode = await createAztecNodeClient(AZTEC_NODE_URL, {});

      const wallet = await EmbeddedWallet.create(aztecNode, {
        pxeConfig: {
          dataDirectory: "pxe-web",
          proverEnabled: false,
        },
      });

      const accountManager = await wallet.createSchnorrAccount(
        INITIAL_TEST_SECRET_KEYS[0],
        INITIAL_TEST_ACCOUNT_SALTS[0],
      );

      set({
        wallet,
        address: accountManager.address,
        walletType: "embedded",
        isConnected: true,
        isConnecting: false,
      });
    } catch (error: any) {
      set({
        error: error.message || "Failed to connect embedded wallet",
        isConnecting: false,
      });
    }
  },

  disconnect: () => {
    const { _disconnectUnsub, _discoverySession, _provider } = get();
    _disconnectUnsub?.();
    _discoverySession?.cancel();
    _provider?.disconnect().catch(() => {});

    set({ ...initialState });
  },
}));
