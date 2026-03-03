import { create } from "zustand";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import {
  INITIAL_TEST_SECRET_KEYS,
  INITIAL_TEST_ACCOUNT_SALTS,
} from "@aztec/accounts/testing";
import { AZTEC_NODE_URL } from "../config";

interface WalletState {
  wallet: EmbeddedWallet | null;
  address: AztecAddress | null;
  isConnecting: boolean;
  isConnected: boolean;
  error: string | null;
  connect: () => Promise<void>;
  disconnect: () => void;
}

export const useWalletStore = create<WalletState>((set, get) => ({
  wallet: null,
  address: null,
  isConnecting: false,
  isConnected: false,
  error: null,

  connect: async () => {
    if (get().isConnecting || get().isConnected) return;

    set({ isConnecting: true, error: null });

    try {
      const aztecNode = await createAztecNodeClient(AZTEC_NODE_URL, {});

      const wallet = await EmbeddedWallet.create(aztecNode, {
        pxeConfig: {
          dataDirectory: "pxe-web",
          proverEnabled: false,
        },
      });

      // Register first test account
      const accountManager = await wallet.createSchnorrAccount(
        INITIAL_TEST_SECRET_KEYS[0],
        INITIAL_TEST_ACCOUNT_SALTS[0],
      );

      set({
        wallet,
        address: accountManager.address,
        isConnected: true,
        isConnecting: false,
      });
    } catch (error: any) {
      set({
        error: error.message || "Failed to connect",
        isConnecting: false,
      });
    }
  },

  disconnect: () => {
    set({
      wallet: null,
      address: null,
      isConnected: false,
      error: null,
    });
  },
}));
