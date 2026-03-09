import { useState, useCallback, useEffect } from "react";
import { useAztecWallet } from "../wallet/useAztecWallet";
import { AZTEC_NODE_URL, DRIPPER_ADDRESS, TOKEN_ADDRESS } from "../config";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import {
  DripperContract,
  DripperContractArtifact,
} from "@defi-wonderland/aztec-standards/dist/src/artifacts/Dripper.js";
import {
  TokenContractArtifact,
} from "@defi-wonderland/aztec-standards/dist/src/artifacts/Token.js";
import DripperArtifactJson from "@defi-wonderland/aztec-standards/target/dripper-Dripper.json";
import TokenArtifactJson from "@defi-wonderland/aztec-standards/target/token_contract-Token.json";

export function DripperDisplay() {
  const {
    wallet,
    address,
    sponsoredFpcAddress,
    isConnected,
    registerContractArtifact,
  } = useAztecWallet();

  const [amount, setAmount] = useState("100");
  const [dripping, setDripping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [contractsRegistered, setContractsRegistered] = useState(false);
  const [registering, setRegistering] = useState(false);

  const hasAddresses = Boolean(DRIPPER_ADDRESS && TOKEN_ADDRESS);

  // Register contracts with PXE when connected
  useEffect(() => {
    if (!wallet || !isConnected || !hasAddresses) return;

    let cancelled = false;
    const dripperAddress = AztecAddress.fromString(DRIPPER_ADDRESS);
    const tokenAddress = AztecAddress.fromString(TOKEN_ADDRESS);

    // Register artifacts for EIP-712 signing
    registerContractArtifact(dripperAddress, DripperContractArtifact, DripperArtifactJson);
    registerContractArtifact(tokenAddress, TokenContractArtifact, TokenArtifactJson);

    (async () => {
      setRegistering(true);
      setContractsRegistered(false);
      try {
        const aztecNode = createAztecNodeClient(AZTEC_NODE_URL);

        const dripperInst = await aztecNode.getContract(dripperAddress);
        if (cancelled) return;
        if (!dripperInst) {
          setError("Dripper contract not found on-chain. Run: yarn deploy:dripper");
          return;
        }
        await wallet.registerContract(dripperInst, DripperContractArtifact);

        const tokenInst = await aztecNode.getContract(tokenAddress);
        if (cancelled) return;
        if (!tokenInst) {
          setError("Token contract not found on-chain. Run: yarn deploy:dripper");
          return;
        }
        await wallet.registerContract(tokenInst, TokenContractArtifact);

        if (!cancelled) {
          console.log("[dripper] Both contracts registered with PXE");
          setContractsRegistered(true);
        }
      } catch (err: any) {
        if (!cancelled) {
          console.warn("[dripper] Registration failed:", err.message);
          setError("Failed to register contracts: " + err.message);
        }
      } finally {
        if (!cancelled) setRegistering(false);
      }
    })();

    return () => { cancelled = true; };
  }, [wallet, isConnected, hasAddresses]);

  // Call drip_to_private on the Dripper contract
  const dripPrivate = useCallback(async () => {
    if (!wallet || !address || !hasAddresses) return;
    setDripping(true);
    setError(null);
    setSuccess(null);

    try {
      const dripperAddress = AztecAddress.fromString(DRIPPER_ADDRESS);
      const tokenAddress = AztecAddress.fromString(TOKEN_ADDRESS);
      const parsedAmount = BigInt(amount);

      const dripper = await DripperContract.at(dripperAddress, wallet);
      await dripper.methods.drip_to_private(tokenAddress, parsedAmount).send({
        from: address,
        fee: sponsoredFpcAddress
          ? { paymentMethod: new SponsoredFeePaymentMethod(sponsoredFpcAddress) }
          : undefined,
      });

      setSuccess(`Dripped ${amount} DRIP tokens privately!`);
    } catch (err: any) {
      console.error("[dripper] drip_to_private failed:", err);
      setError(err.message || "Failed to drip");
    } finally {
      setDripping(false);
    }
  }, [wallet, address, hasAddresses, amount, sponsoredFpcAddress]);

  if (!isConnected) {
    return (
      <div style={styles.card}>
        <p style={styles.muted}>Connect your wallet to use the Dripper.</p>
      </div>
    );
  }

  if (!hasAddresses) {
    return (
      <div style={styles.card}>
        <h2 style={styles.title}>Dripper</h2>
        <p style={styles.muted}>
          No Dripper/Token addresses configured.<br />
          Run <code>yarn deploy:dripper</code> then set VITE_DRIPPER_ADDRESS and VITE_TOKEN_ADDRESS.
        </p>
      </div>
    );
  }

  const canInteract = contractsRegistered && !registering;

  return (
    <div style={styles.card}>
      <h2 style={styles.title}>Dripper</h2>

      {registering && (
        <p style={styles.muted}>Registering contracts with PXE...</p>
      )}

      <div style={styles.addressInfo}>
        <div style={styles.addressRow}>
          <span style={styles.label}>Dripper:</span>
          <span style={styles.mono}>{DRIPPER_ADDRESS.slice(0, 10)}...{DRIPPER_ADDRESS.slice(-6)}</span>
        </div>
        <div style={styles.addressRow}>
          <span style={styles.label}>Token:</span>
          <span style={styles.mono}>{TOKEN_ADDRESS.slice(0, 10)}...{TOKEN_ADDRESS.slice(-6)}</span>
        </div>
      </div>

      <div style={styles.inputGroup}>
        <label style={styles.label}>Amount</label>
        <input
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          style={styles.input}
          min="1"
          disabled={!canInteract || dripping}
        />
      </div>

      <div style={styles.actions}>
        <button
          onClick={dripPrivate}
          disabled={!canInteract || dripping || !amount}
          style={{ ...styles.button, ...styles.primaryButton }}
        >
          {dripping ? "Signing & Sending..." : "Drip Private"}
        </button>
      </div>

      {success && <p style={styles.success}>{success}</p>}
      {error && <p style={styles.error}>{error}</p>}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  card: {
    background: "var(--bg-surface)",
    border: "1px solid var(--border)",
    borderRadius: "12px",
    padding: "2rem",
    maxWidth: "400px",
    width: "100%",
  },
  title: {
    fontSize: "1.25rem",
    fontWeight: 600,
    marginBottom: "1rem",
  },
  addressInfo: {
    display: "flex",
    flexDirection: "column",
    gap: "0.25rem",
    marginBottom: "1rem",
    fontSize: "0.8rem",
  },
  addressRow: {
    display: "flex",
    gap: "0.5rem",
    alignItems: "center",
  },
  label: {
    color: "var(--text-muted)",
    fontWeight: 500,
    fontSize: "0.875rem",
  },
  mono: {
    fontFamily: "var(--font-mono)",
    color: "var(--text-muted)",
  },
  inputGroup: {
    display: "flex",
    flexDirection: "column",
    gap: "0.25rem",
    marginBottom: "1rem",
  },
  input: {
    padding: "0.5rem 0.75rem",
    background: "var(--bg-surface-hover)",
    color: "var(--text)",
    border: "1px solid var(--border)",
    borderRadius: "8px",
    fontSize: "1rem",
    fontFamily: "var(--font-mono)",
  },
  actions: {
    display: "flex",
    gap: "0.75rem",
    justifyContent: "center",
  },
  button: {
    padding: "0.625rem 1.25rem",
    background: "var(--bg-surface-hover)",
    color: "var(--text)",
    border: "1px solid var(--border)",
    borderRadius: "8px",
    fontWeight: 500,
    cursor: "pointer",
  },
  primaryButton: {
    background: "var(--accent)",
    border: "1px solid var(--accent)",
    color: "#fff",
  },
  muted: {
    color: "var(--text-muted)",
    lineHeight: 1.8,
  },
  success: {
    color: "var(--success, #4caf50)",
    fontSize: "0.875rem",
    marginTop: "0.75rem",
    textAlign: "center" as const,
  },
  error: {
    color: "var(--error)",
    fontSize: "0.875rem",
    marginTop: "0.75rem",
    textAlign: "center" as const,
  },
};
