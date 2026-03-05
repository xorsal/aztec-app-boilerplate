import { useAztecWallet } from "../wallet/useAztecWallet";

export function ConnectButton() {
  const {
    isConnected, isConnecting, address, evmAddress, error,
    accountVersion, setAccountVersion, connect, disconnect,
  } = useAztecWallet();

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
          <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", opacity: 0.7 }}>
            EIP-712 {accountVersion.toUpperCase()}
          </span>
          {shortEvm && (
            <code style={{ fontSize: "0.75rem", color: "var(--text-muted)", opacity: 0.7, display: "block" }}>
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
    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "0.5rem" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <VersionToggle value={accountVersion} onChange={setAccountVersion} disabled={isConnecting} />
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
      </div>
      {error && (
        <p style={{ color: "var(--error)", fontSize: "0.875rem", marginTop: "0.5rem" }}>
          {error}
        </p>
      )}
    </div>
  );
}

function VersionToggle({
  value,
  onChange,
  disabled,
}: {
  value: 'v1' | 'v2';
  onChange: (v: 'v1' | 'v2') => void;
  disabled: boolean;
}) {
  return (
    <div
      style={{
        display: "inline-flex",
        borderRadius: "6px",
        border: "1px solid var(--border)",
        overflow: "hidden",
        opacity: disabled ? 0.5 : 1,
      }}
    >
      {(['v1', 'v2'] as const).map((v) => (
        <button
          key={v}
          onClick={() => onChange(v)}
          disabled={disabled}
          style={{
            padding: "0.35rem 0.6rem",
            fontSize: "0.75rem",
            fontWeight: value === v ? 600 : 400,
            background: value === v ? "var(--accent)" : "var(--bg-surface)",
            color: value === v ? "#fff" : "var(--text-muted)",
            border: "none",
            cursor: disabled ? "default" : "pointer",
          }}
        >
          {v.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
