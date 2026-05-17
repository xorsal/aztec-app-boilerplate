import { useAztecWallet } from "../wallet/useAztecWallet";
import { EmojiGrid } from "./EmojiGrid";

export function ConnectButton() {
  const {
    isConnected,
    isConnecting,
    isDiscovering,
    address,
    walletType,
    error,
    providers,
    verificationEmojis,
    hasPendingVerification,
    startDiscovery,
    cancelDiscovery,
    connectExtension,
    confirmConnection,
    cancelConnection,
    connectEmbedded,
    disconnect,
  } = useAztecWallet();

  // State D: Connected
  if (isConnected && address) {
    const shortAddr = address.toString().slice(0, 10) + "...";
    return (
      <div style={styles.row}>
        <span style={styles.badge}>
          {walletType === "extension" ? "Extension" : "Embedded"}
        </span>
        <code style={styles.address}>{shortAddr}</code>
        <button onClick={disconnect} style={styles.secondaryBtn}>
          Disconnect
        </button>
      </div>
    );
  }

  // State C: Emoji verification
  if (hasPendingVerification && verificationEmojis) {
    return (
      <div style={styles.panel}>
        <EmojiGrid emojis={verificationEmojis} />
        <div style={styles.row}>
          <button onClick={cancelConnection} style={styles.secondaryBtn}>
            Cancel
          </button>
          <button onClick={confirmConnection} style={styles.primaryBtn}>
            Confirm Match
          </button>
        </div>
      </div>
    );
  }

  // State B: Discovering / selecting
  if (isDiscovering || providers.length > 0) {
    return (
      <div style={styles.panel}>
        <p style={styles.label}>
          {isDiscovering ? "Looking for wallets..." : "Select a wallet"}
        </p>
        {providers.length > 0 && (
          <div style={styles.providerList}>
            {providers.map((p) => (
              <button
                key={p.id}
                onClick={() => connectExtension(p)}
                disabled={isConnecting}
                style={styles.providerBtn}
              >
                {p.icon && <img src={p.icon} alt="" style={styles.icon} />}
                <span>{p.name}</span>
              </button>
            ))}
          </div>
        )}
        {isDiscovering && providers.length === 0 && (
          <p style={styles.muted}>Waiting for wallet approval...</p>
        )}
        <div style={styles.row}>
          <button onClick={cancelDiscovery} style={styles.secondaryBtn}>
            Cancel
          </button>
          <button
            onClick={connectEmbedded}
            disabled={isConnecting}
            style={styles.secondaryBtn}
          >
            {isConnecting ? "Connecting..." : "Use Embedded"}
          </button>
        </div>
        {error && <p style={styles.error}>{error}</p>}
      </div>
    );
  }

  // State A: Disconnected — choose wallet type
  return (
    <div style={styles.panel}>
      <div style={styles.row}>
        <button onClick={startDiscovery} style={styles.primaryBtn}>
          Connect Wallet
        </button>
        <button
          onClick={connectEmbedded}
          disabled={isConnecting}
          style={styles.secondaryBtn}
        >
          {isConnecting ? "Connecting..." : "Embedded"}
        </button>
      </div>
      {error && <p style={styles.error}>{error}</p>}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  panel: {
    display: "flex",
    flexDirection: "column",
    gap: "0.75rem",
    alignItems: "center",
  },
  row: {
    display: "flex",
    alignItems: "center",
    gap: "0.75rem",
  },
  label: {
    fontSize: "0.875rem",
    fontWeight: 600,
    color: "var(--text)",
  },
  muted: {
    fontSize: "0.8125rem",
    color: "var(--text-muted)",
  },
  address: {
    fontSize: "0.875rem",
    color: "var(--text-muted)",
  },
  badge: {
    fontSize: "0.75rem",
    padding: "0.125rem 0.5rem",
    borderRadius: "9999px",
    background: "var(--accent)",
    color: "#fff",
    fontWeight: 600,
  },
  primaryBtn: {
    padding: "0.625rem 1.25rem",
    background: "var(--accent)",
    color: "#fff",
    borderRadius: "8px",
    fontWeight: 600,
  },
  secondaryBtn: {
    padding: "0.5rem 1rem",
    background: "var(--bg-surface)",
    color: "var(--text)",
    border: "1px solid var(--border)",
    borderRadius: "8px",
  },
  providerList: {
    display: "flex",
    flexDirection: "column",
    gap: "0.5rem",
    width: "100%",
    maxWidth: "260px",
  },
  providerBtn: {
    display: "flex",
    alignItems: "center",
    gap: "0.75rem",
    padding: "0.625rem 1rem",
    background: "var(--bg-surface)",
    color: "var(--text)",
    border: "1px solid var(--border)",
    borderRadius: "8px",
    fontWeight: 500,
    cursor: "pointer",
    textAlign: "left" as const,
  },
  icon: {
    width: "24px",
    height: "24px",
    borderRadius: "4px",
  },
  error: {
    color: "var(--error)",
    fontSize: "0.8125rem",
  },
};
