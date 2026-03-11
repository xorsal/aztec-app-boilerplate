interface EmojiGridProps {
  emojis: string;
}

export function EmojiGrid({ emojis }: EmojiGridProps) {
  // emojis is a string of 9 emoji characters — render as 3x3 grid
  const chars = [...emojis];

  return (
    <div style={styles.container}>
      <div style={styles.grid}>
        {chars.map((emoji, i) => (
          <div key={i} style={styles.cell}>
            {emoji}
          </div>
        ))}
      </div>
      <p style={styles.hint}>
        Verify this matches your wallet
      </p>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "0.75rem",
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(3, 1fr)",
    gap: "0.5rem",
    padding: "1rem",
    background: "var(--bg)",
    borderRadius: "12px",
    border: "1px solid var(--border)",
  },
  cell: {
    fontSize: "2rem",
    width: "3rem",
    height: "3rem",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  hint: {
    color: "var(--text-muted)",
    fontSize: "0.8125rem",
  },
};
