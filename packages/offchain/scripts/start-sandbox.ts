import { spawn, ChildProcess } from "child_process";
import { EventEmitter } from "events";
import { createAztecNodeClient } from "@aztec/aztec.js/node";

let activeSandboxManager: SandboxManager | null = null;
let signalHandlersSetup = false;

function setupSignalHandlers(): void {
  if (signalHandlersSetup) return;

  const handleShutdown = async (): Promise<void> => {
    if (activeSandboxManager) {
      try {
        await activeSandboxManager.stop();
      } catch (err) {
        console.error("Error stopping manager:", err);
      }
      activeSandboxManager = null;
    }
    process.exit(0);
  };

  process.on("SIGINT", () => handleShutdown());
  process.on("SIGTERM", () => handleShutdown());
  signalHandlersSetup = true;
}

class SandboxManager extends EventEmitter {
  public process: ChildProcess | null = null;
  public isReady = false;
  public isExternalSandbox = false;
  public verbose: boolean;

  private timers: Record<string, NodeJS.Timeout> = {};
  private stderrBuffer: string[] = [];

  constructor(options: { verbose?: boolean } = {}) {
    super();
    this.verbose = options.verbose ?? Boolean(process.env.CI);
    activeSandboxManager = this;
    setupSignalHandlers();
  }

  private clearTimer(name: string): void {
    if (this.timers[name]) {
      clearTimeout(this.timers[name]);
      delete this.timers[name];
    }
  }

  private cleanupTimers(): void {
    for (const name of Object.keys(this.timers)) {
      this.clearTimer(name);
    }
  }

  private resetState(): void {
    this.cleanupTimers();
    this.process = null;
    this.isReady = false;
    this.stderrBuffer = [];
    this.isExternalSandbox = false;
    activeSandboxManager = null;
  }

  async checkSandboxConnectivity(): Promise<void> {
    console.time("✅ Sandbox ready");

    const maxRetries = 60;
    const retryDelayMs = 3000;
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const aztecNode = await createAztecNodeClient(
          "http://localhost:8080",
          {},
        );
        const nodeInfo = await aztecNode.getNodeInfo();
        console.timeEnd("✅ Sandbox ready");
        console.log(`🔧 Node version: ${nodeInfo.nodeVersion}`);
        return;
      } catch (error: any) {
        lastError = error;
        if (attempt < maxRetries) {
          if (this.verbose) {
            console.log(
              `⏳ Sandbox not ready (attempt ${attempt}/${maxRetries}), retrying in ${retryDelayMs / 1000}s...`,
            );
          }
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
        }
      }
    }

    throw new Error(
      `Failed to connect to sandbox after ${maxRetries} attempts: ${lastError?.message}`,
    );
  }

  async start(): Promise<SandboxManager> {
    if (this.isReady || this.process) {
      throw new Error("Cannot start sandbox — already running or starting");
    }

    return new Promise((resolve, reject) => {
      console.log("🚀 Starting Aztec sandbox");
      let resolved = false;

      const safeResolve = (value: SandboxManager): void => {
        if (!resolved) {
          resolved = true;
          resolve(value);
        }
      };

      const safeReject = (error: Error): void => {
        if (!resolved) {
          resolved = true;
          reject(error);
        }
      };

      // Startup timeout
      this.timers["startupTimeout"] = setTimeout(() => {
        this.cleanup();
        safeReject(new Error("❌ Sandbox startup timed out after 180 seconds"));
      }, 180000);

      // Check connectivity in parallel
      console.log("🔍 Waiting for sandbox to be ready");
      (async () => {
        try {
          await this.checkSandboxConnectivity();
          this.cleanupTimers();
          this.isReady = true;
          safeResolve(this);
        } catch (error: any) {
          this.resetState();
          safeReject(new Error(`Failed to connect: ${error.message}`));
        }
      })();

      // Spawn sandbox process
      try {
        const l1RpcUrl = process.env.L1_RPC_URL || "http://127.0.0.1:8545";
        this.process = spawn(
          "aztec",
          ["start", "--sandbox", "--l1-rpc-urls", l1RpcUrl],
          { stdio: "pipe" },
        );

        if (this.verbose && this.process.stdout) {
          this.process.stdout.on("data", (data: Buffer) => {
            console.log(`📡 Sandbox: ${data.toString().trim()}`);
          });
        }

        if (this.process.stderr) {
          this.process.stderr.on("data", (data: Buffer) => {
            const output = data.toString().trim();
            if (output) {
              this.stderrBuffer.push(output);
              if (output.includes("port is already")) {
                this.clearTimer("startupTimeout");
                console.log(
                  "ℹ️ Port in use, checking if existing sandbox is responsive",
                );
                if (this.process) this.process.kill("SIGTERM");
                this.process = null;

                this.checkSandboxConnectivity()
                  .then(() => {
                    this.isExternalSandbox = true;
                    this.isReady = true;
                    console.log("✅ Connected to existing external sandbox");
                    safeResolve(this);
                  })
                  .catch(() => {
                    this.resetState();
                    safeReject(
                      new Error("Port 8080 in use but sandbox not responsive"),
                    );
                  });
              }
            }
          });
        }

        this.process.on("error", (error: any) => {
          this.resetState();
          safeReject(
            new Error(
              error.code === "ENOENT"
                ? "Aztec CLI not found. Install with aztec-up."
                : `Failed to start sandbox: ${error.message}`,
            ),
          );
        });

        this.process.on("exit", (code, signal) => {
          if (!this.isReady) {
            const stderr =
              this.stderrBuffer.length > 0
                ? `\nStderr:\n${this.stderrBuffer.slice(-10).join("\n")}`
                : "";
            this.resetState();
            safeReject(
              new Error(`Sandbox exited (code=${code}, signal=${signal})${stderr}`),
            );
          }
        });
      } catch (error: any) {
        this.resetState();
        safeReject(new Error(`Failed to spawn: ${error.message}`));
      }
    });
  }

  async stop(): Promise<void> {
    if (!this.isReady && !this.process) return;

    if (this.isExternalSandbox) {
      console.log("🔌 Disconnecting from external sandbox");
      this.resetState();
      return;
    }

    if (!this.process) {
      this.resetState();
      return;
    }

    console.log("🛑 Stopping Aztec sandbox process");

    return new Promise((resolve) => {
      this.timers["forceKillTimeout"] = setTimeout(() => {
        if (this.process) {
          console.log("🔥 Force killing sandbox process");
          this.process.kill("SIGKILL");
        }
      }, 5000);

      this.process!.once("exit", () => {
        this.resetState();
        resolve();
      });

      this.process!.kill("SIGTERM");
    });
  }

  cleanup(): void {
    if (!this.isExternalSandbox && this.process) {
      this.process.kill("SIGTERM");
    }
    this.resetState();
  }
}

async function startSandbox(
  options: { verbose?: boolean } = {},
): Promise<SandboxManager> {
  const manager = new SandboxManager(options);
  await manager.start();
  return manager;
}

export { startSandbox, SandboxManager };
