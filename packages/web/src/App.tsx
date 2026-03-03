import { ConnectButton } from "./components/ConnectButton";
import { CounterDisplay } from "./components/CounterDisplay";

export function App() {
  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1 style={styles.logo}>Aztec App</h1>
        <ConnectButton />
      </header>

      <main style={styles.main}>
        <CounterDisplay />
      </main>

      <footer style={styles.footer}>
        <p>
          Built with{" "}
          <a
            href="https://aztec.network"
            target="_blank"
            rel="noopener noreferrer"
            style={styles.link}
          >
            Aztec
          </a>{" "}
          v4
        </p>
      </footer>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "1rem 2rem",
    borderBottom: "1px solid var(--border)",
  },
  logo: {
    fontSize: "1.25rem",
    fontWeight: 700,
  },
  main: {
    flex: 1,
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    padding: "2rem",
  },
  footer: {
    textAlign: "center" as const,
    padding: "1rem",
    color: "var(--text-muted)",
    fontSize: "0.875rem",
    borderTop: "1px solid var(--border)",
  },
  link: {
    color: "var(--accent)",
    textDecoration: "none",
  },
};
