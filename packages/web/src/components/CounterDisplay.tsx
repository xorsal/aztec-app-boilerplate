import { useState, useCallback, useEffect } from "react";
import { useAztecWallet } from "../wallet/useAztecWallet";
import { CONTRACT_ADDRESS, AZTEC_NODE_URL } from "../config";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { CounterContract } from "../../../contracts/artifacts/Counter.js";

export function CounterDisplay() {
  const { wallet, address, sponsoredFpcAddress, isConnected, registerContractArtifact } = useAztecWallet();
  const [counter, setCounter] = useState<bigint | null>(null);
  const [loading, setLoading] = useState(false);
  const [incrementing, setIncrementing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Register Counter contract with PXE and for EIP-712 signing
  useEffect(() => {
    if (!wallet || !isConnected || !CONTRACT_ADDRESS) return;
    const contractAddress = AztecAddress.fromString(CONTRACT_ADDRESS);

    // Register artifact for readable EIP-712 signing in MetaMask
    registerContractArtifact(contractAddress, CounterContract.artifact);

    // Register with PXE so it knows about this contract (fetch instance from node)
    (async () => {
      try {
        const aztecNode = createAztecNodeClient(AZTEC_NODE_URL);
        const instance = await aztecNode.getContract(contractAddress);
        if (instance) {
          await wallet.registerContract(instance, CounterContract.artifact);
          console.log("[counter] Contract registered with PXE");
        } else {
          console.warn("[counter] Contract not found on-chain at", CONTRACT_ADDRESS);
        }
      } catch (err: any) {
        console.warn("[counter] Failed to register contract with PXE:", err.message);
      }
    })();
  }, [wallet, isConnected]);

  const getContract = useCallback(async () => {
    if (!wallet || !CONTRACT_ADDRESS) return null;
    const contractAddress = AztecAddress.fromString(CONTRACT_ADDRESS);
    return CounterContract.at(contractAddress, wallet);
  }, [wallet]);

  const fetchCounter = useCallback(async () => {
    if (!address) return;
    setLoading(true);
    setError(null);
    try {
      const contract = await getContract();
      if (!contract) throw new Error("Contract not available");
      const value = await contract.methods
        .get_counter()
        .simulate({ from: address });
      setCounter(value);
    } catch (err: any) {
      setError(err.message || "Failed to read counter");
    } finally {
      setLoading(false);
    }
  }, [address, getContract]);

  const increment = useCallback(async () => {
    if (!address) return;
    setIncrementing(true);
    setError(null);
    try {
      const contract = await getContract();
      if (!contract) throw new Error("Contract not available");
      await contract.methods.increment().send({
        from: address,
        fee: sponsoredFpcAddress
          ? { paymentMethod: new SponsoredFeePaymentMethod(sponsoredFpcAddress) }
          : undefined,
      });
      // Re-fetch after increment
      const value = await contract.methods
        .get_counter()
        .simulate({ from: address });
      setCounter(value);
    } catch (err: any) {
      setError(err.message || "Failed to increment");
    } finally {
      setIncrementing(false);
    }
  }, [address, getContract]);

  if (!isConnected) {
    return (
      <div style={styles.card}>
        <p style={styles.muted}>Connect your wallet to interact with the counter.</p>
      </div>
    );
  }

  if (!CONTRACT_ADDRESS) {
    return (
      <div style={styles.card}>
        <p style={styles.muted}>
          Set <code>VITE_CONTRACT_ADDRESS</code> in your <code>.env</code> file.
          <br />
          Run <code>yarn deploy</code> to deploy the Counter contract first.
        </p>
      </div>
    );
  }

  return (
    <div style={styles.card}>
      <h2 style={styles.title}>Counter</h2>

      <div style={styles.value}>
        {counter !== null ? counter.toString() : "\u2014"}
      </div>

      <div style={styles.actions}>
        <button onClick={fetchCounter} disabled={loading} style={styles.button}>
          {loading ? "Reading..." : "Read"}
        </button>
        <button
          onClick={increment}
          disabled={incrementing}
          style={{ ...styles.button, ...styles.primaryButton }}
        >
          {incrementing ? "Sending tx..." : "Increment"}
        </button>
      </div>

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
  value: {
    fontSize: "3rem",
    fontWeight: 700,
    textAlign: "center" as const,
    padding: "1.5rem 0",
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
  error: {
    color: "var(--error)",
    fontSize: "0.875rem",
    marginTop: "0.75rem",
    textAlign: "center" as const,
  },
};
