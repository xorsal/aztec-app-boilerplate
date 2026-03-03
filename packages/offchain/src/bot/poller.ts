/**
 * Simple polling mechanism that calls a callback at a fixed interval.
 * Handles async callbacks gracefully (waits for completion before next poll).
 */
export function createPoller(
  callback: () => Promise<void>,
  intervalMs: number,
) {
  let timer: NodeJS.Timeout | null = null;
  let running = false;

  async function poll() {
    if (!running) return;

    try {
      await callback();
    } catch (error) {
      console.error("⚠️  Poll error:", error);
    }

    if (running) {
      timer = setTimeout(poll, intervalMs);
    }
  }

  return {
    start() {
      running = true;
      console.log(`🔄 Polling started (every ${intervalMs}ms)`);
      poll();
    },
    stop() {
      running = false;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      console.log("⏹️  Polling stopped");
    },
  };
}
