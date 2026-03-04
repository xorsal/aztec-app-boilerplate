import { create } from "zustand";
import {
  createWalletClient,
  custom,
  keccak256,
  toBytes,
  type Hex,
  type WalletClient,
} from "viem";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import {
  Eip712Account,
  Eip712AccountEntrypoint,
} from "@aztec-app/eip712";
import { AZTEC_NODE_URL, EIP712_CHAIN_ID } from "../config";
import { MetaMaskEip712SigningDelegate } from "./signingDelegate";
import {
  recoverPublicKeyFromSignature,
  getPublicKeyRecoveryMessage,
} from "./evmPublicKeyRecovery";

interface WalletState {
  wallet: EmbeddedWallet | null;
  address: AztecAddress | null;
  evmAddress: Hex | null;
  walletClient: WalletClient | null;
  signingDelegate: MetaMaskEip712SigningDelegate | null;
  isConnecting: boolean;
  isConnected: boolean;
  error: string | null;
  connect: () => Promise<void>;
  disconnect: () => void;
}

export const useWalletStore = create<WalletState>((set, get) => ({
  wallet: null,
  address: null,
  evmAddress: null,
  walletClient: null,
  signingDelegate: null,
  isConnecting: false,
  isConnected: false,
  error: null,

  connect: async () => {
    if (get().isConnecting || get().isConnected) return;

    set({ isConnecting: true, error: null });

    try {
      // 1. Connect MetaMask via window.ethereum
      const ethereum = (window as any).ethereum;
      if (!ethereum) {
        throw new Error("No Ethereum wallet found. Install MetaMask.");
      }

      const accounts: Hex[] = await ethereum.request({
        method: "eth_requestAccounts",
      });
      if (!accounts.length) {
        throw new Error("No accounts returned from wallet");
      }
      const evmAddress = accounts[0];

      // 2. Create viem wallet client
      const walletClient = createWalletClient({
        account: evmAddress,
        transport: custom(ethereum),
      });

      // 3. Sign message to recover public key
      const message = getPublicKeyRecoveryMessage(evmAddress);
      const signature = await walletClient.signMessage({
        account: evmAddress,
        message,
      });

      const publicKey = await recoverPublicKeyFromSignature(
        message,
        signature,
      );

      // 4. Derive secret key and salt from signature
      const signatureHash = keccak256(toBytes(signature));
      const secretKey = Buffer.from(signatureHash.slice(2), "hex");
      const salt = Buffer.from(
        evmAddress.slice(2).padStart(64, "0"),
        "hex",
      ).slice(0, 32);

      // 5. Create EIP-712 account
      const chainId = EIP712_CHAIN_ID;
      const eip712Account = new Eip712Account(undefined, chainId);

      // 6. Create signing delegate
      const signingDelegate = new MetaMaskEip712SigningDelegate(
        walletClient,
        evmAddress,
        chainId,
      );

      // 7. Connect to Aztec node and create embedded wallet with EIP-712 entrypoint
      const aztecNode = await createAztecNodeClient(AZTEC_NODE_URL, {});

      const entrypoint = new Eip712AccountEntrypoint(signingDelegate);

      const wallet = await EmbeddedWallet.create(aztecNode, {
        pxeConfig: {
          dataDirectory: "pxe-web",
          proverEnabled: false,
        },
      });

      // 8. Register the EIP-712 account with PXE
      const accountAddress = await wallet.registerEcdsaSecp256k1Account(
        secretKey,
        salt,
        publicKey.x,
        publicKey.y,
      );

      set({
        wallet,
        address: accountAddress,
        evmAddress,
        walletClient,
        signingDelegate,
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
      evmAddress: null,
      walletClient: null,
      signingDelegate: null,
      isConnected: false,
      error: null,
    });
  },
}));
