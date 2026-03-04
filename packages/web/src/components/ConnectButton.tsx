import { useAztecWallet } from "../wallet/useAztecWallet";

export function ConnectButton() {
  const { isConnected, isConnecting, address, evmAddress, error, connect, disconnect } =
    useAztecWallet();

  if (isConnected && address) {
    const shortAztec = address.toString().slice(0, 10) + "...";
    const shortEvm = evmAddress
      ? evmAddress.slice(0, 6) + "..." + evmAddress.slice(-4)
      : null;

    return (
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
        <div style={{ textAlign: "right" }}>
          <code style={{ fontSize: "0.875rem", color: "var(--text-muted)", display: "block" }}>
            {shortAztec}
          </code>
          {shortEvm && (
            <code style={{ fontSize: "0.75rem", color: "var(--text-muted)", opacity: 0.7 }}>
              {shortEvm}
            </code>
          )}
        </div>
        <button
          onClick={disconnect}
          style={{
            padding: "0.5rem 1rem",
            background: "var(--bg-surface)",
            color: "var(--text)",
            border: "1px solid var(--border)",
            borderRadius: "8px",
          }}
        >
          Disconnect
        </button>
      </div>
    );
  }

  return (
    <div>
      <button
        onClick={connect}
        disabled={isConnecting}
        style={{
          padding: "0.625rem 1.25rem",
          background: isConnecting ? "var(--bg-surface)" : "var(--accent)",
          color: "#fff",
          borderRadius: "8px",
          fontWeight: 600,
          opacity: isConnecting ? 0.7 : 1,
        }}
      >
        {isConnecting ? "Connecting..." : "Connect MetaMask"}
      </button>
      {error && (
        <p style={{ color: "var(--error)", fontSize: "0.875rem", marginTop: "0.5rem" }}>
          {error}
        </p>
      )}
    </div>
  );
}
