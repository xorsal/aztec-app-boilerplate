import { create } from "zustand";
import {
  createWalletClient,
  custom,
  type Hex,
  type WalletClient,
} from "viem";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { Fr } from "@aztec/aztec.js/fields";
import { getContractInstanceFromInstantiationParams } from "@aztec/aztec.js/contracts";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { AccountManager } from "@aztec/aztec.js/wallet";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { TxStatus } from "@aztec/stdlib/tx";
import { SPONSORED_FPC_SALT } from "@aztec/constants";
import { SponsoredFPCContractArtifact } from "@aztec/noir-contracts.js/SponsoredFPC";
import type { ContractArtifact } from "@aztec/stdlib/abi";
import { Eip712AccountContract, Eip712AccountContractV2 } from "@aztec-app/eip712";
import { AZTEC_NODE_URL, EIP712_CHAIN_ID } from "../config";
import { MetaMaskEip712SigningDelegate } from "./signingDelegate";
import { MetaMaskEip712SigningDelegateV2 } from "./signingDelegateV2";
import {
  recoverPublicKeyFromSignature,
  getPublicKeyRecoveryMessage,
} from "./evmPublicKeyRecovery";

type AccountVersion = 'v1' | 'v2';

interface WalletState {
  wallet: EmbeddedWallet | null;
  address: AztecAddress | null;
  evmAddress: Hex | null;
  walletClient: WalletClient | null;
  sponsoredFpcAddress: AztecAddress | null;
  accountVersion: AccountVersion;
  isConnecting: boolean;
  isDeploying: boolean;
  isConnected: boolean;
  error: string | null;
  setAccountVersion: (version: AccountVersion) => void;
  connect: () => Promise<void>;
  disconnect: () => void;
  /** Register a contract artifact for human-readable EIP-712 signing. */
  registerContractArtifact: (address: AztecAddress, artifact: ContractArtifact) => void;
}

export const useWalletStore = create<WalletState>((set, get) => ({
  wallet: null,
  address: null,
  evmAddress: null,
  walletClient: null,
  sponsoredFpcAddress: null,
  accountVersion: 'v1' as AccountVersion,
  isConnecting: false,
  isDeploying: false,
  isConnected: false,
  error: null,

  setAccountVersion: (version: AccountVersion) => {
    if (get().isConnected) return; // Cannot change while connected
    set({ accountVersion: version });
  },

  registerContractArtifact: () => {
    console.warn("[wallet] Cannot register artifact: wallet not connected");
  },

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

      // 4. Create signing delegate (handles MetaMask EIP-712 signing)
      const version = get().accountVersion;
      const signingDelegate = version === 'v2'
        ? new MetaMaskEip712SigningDelegateV2(walletClient, evmAddress, EIP712_CHAIN_ID)
        : new MetaMaskEip712SigningDelegate(walletClient, evmAddress, EIP712_CHAIN_ID);

      // 5. Create EIP-712 account contract with signing delegate
      const accountContract = version === 'v2'
        ? new Eip712AccountContractV2(publicKey.x, publicKey.y, signingDelegate, signingDelegate as MetaMaskEip712SigningDelegateV2)
        : new Eip712AccountContract(publicKey.x, publicKey.y, signingDelegate, signingDelegate as MetaMaskEip712SigningDelegate);

      // 6. Connect to Aztec node and create embedded wallet
      const aztecNode = createAztecNodeClient(AZTEC_NODE_URL);
      const wallet = await EmbeddedWallet.create(aztecNode, {
        pxeConfig: {
          dataDirectory: "pxe-web",
          dataStoreMapSizeKb: 5e5, // 500MB (default is 128GB)
          proverEnabled: false,
        },
      });

      // 7. Create account via AccountManager
      const secretKey = Fr.random();
      const accountManager = await AccountManager.create(
        wallet,
        secretKey,
        accountContract,
        Fr.random(),
      );

      // 8. Register contract with wallet's PXE
      const instance = accountManager.getInstance();
      const artifact = await accountManager.getAccountContract().getContractArtifact();
      await wallet.registerContract(instance, artifact, accountManager.getSecretKey());

      // 9. Patch wallet to support EIP-712 account lookups.
      // EmbeddedWallet only supports built-in account types in getAccountFromAddress(),
      // so we override it so send({ from: accountAddress }) finds our custom Account.
      const eip712AccountObj = await accountManager.getAccount();
      const origGetAccountFromAddress = (wallet as any).getAccountFromAddress.bind(wallet);
      (wallet as any).getAccountFromAddress = async (address: AztecAddress) => {
        if (address.equals(accountManager.address)) {
          return eip712AccountObj;
        }
        return origGetAccountFromAddress(address);
      };

      const accountAddress = accountManager.address;

      // 10. Register SponsoredFPC for fee payment
      const sponsoredFPCInstance =
        await getContractInstanceFromInstantiationParams(
          SponsoredFPCContractArtifact,
          { salt: new Fr(SPONSORED_FPC_SALT) },
        );
      await wallet.registerContract(
        sponsoredFPCInstance,
        SponsoredFPCContractArtifact,
      );
      signingDelegate.registerContractArtifact(
        sponsoredFPCInstance.address,
        SponsoredFPCContractArtifact,
      );

      set({
        wallet,
        address: accountAddress,
        evmAddress,
        walletClient,
        sponsoredFpcAddress: sponsoredFPCInstance.address,
        isConnected: true,
        isConnecting: false,
        isDeploying: true,
        registerContractArtifact: (addr: AztecAddress, artifact: ContractArtifact) => {
          signingDelegate.registerContractArtifact(addr, artifact);
        },
      });

      // 11. Deploy account contract if not already deployed
      try {
        const metadata = await wallet.getContractMetadata(accountAddress);
        if (!metadata.isContractInitialized) {
          console.log(`[wallet] Deploying EIP-712 ${version} account...`);
          const deployMethod = await accountManager.getDeployMethod();
          const paymentMethod = new SponsoredFeePaymentMethod(
            sponsoredFPCInstance.address,
          );
          await deployMethod.send({
            from: AztecAddress.ZERO,
            fee: { paymentMethod },
            skipClassPublication: true,
            skipInstancePublication: true,
            wait: { timeout: 120, waitForStatus: TxStatus.PROPOSED },
          });
          console.log("[wallet] Account deployed successfully");
        } else {
          console.log("[wallet] Account already deployed");
        }
      } catch (deployError: any) {
        console.warn("[wallet] Account deployment failed:", deployError.message);
        // Non-fatal: account is registered locally, deployment can be retried
      } finally {
        set({ isDeploying: false });
      }
    } catch (error: any) {
      set({
        error: error.message || "Failed to connect",
        isConnecting: false,
      });
    }
  },

  disconnect: () => {
    const { wallet, accountVersion } = get();
    if (wallet) {
      wallet.stop().catch(() => {});
    }
    set({
      wallet: null,
      address: null,
      evmAddress: null,
      walletClient: null,
      sponsoredFpcAddress: null,
      accountVersion,
      isConnected: false,
      isDeploying: false,
      error: null,
      registerContractArtifact: () => {
        console.warn("[wallet] Cannot register artifact: wallet not connected");
      },
    });
  },
}));
