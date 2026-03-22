import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";
import { nodeBuiltinsShim, fixStaticFieldInit } from "./vite-plugins";

const crossOriginHeaders = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "credentialless",
  "Cross-Origin-Resource-Policy": "cross-origin",
};

export default defineConfig({
  plugins: [
    nodeBuiltinsShim(),
    react(),
    wasm(),
    topLevelAwait(),
    fixStaticFieldInit(),
    nodePolyfills({
      include: ["buffer", "crypto", "util", "assert", "process", "stream", "path", "events"],
      globals: { Buffer: true, global: true, process: true },
      exclude: ["fs", "net", "tty"],
    }),
  ],
  assetsInclude: ["**/*.wasm"],
  define: { global: "globalThis" },
  worker: { format: "es" },
  esbuild: { target: "esnext" },
  resolve: {
    alias: { pino: "pino/browser.js" },
    dedupe: ["@aztec/foundation", "@aztec/stdlib", "@aztec/aztec.js", "@noble/curves"],
  },
  server: {
    port: 3001,
    headers: crossOriginHeaders,
    fs: { allow: [".."] },
  },
  preview: {
    port: 3001,
    headers: crossOriginHeaders,
  },
  build: {
    target: "esnext",
    minify: "esbuild",
    chunkSizeWarningLimit: 2000,
    rollupOptions: { output: { format: "es" } },
  },
  optimizeDeps: {
    exclude: ["@aztec/noir-acvm_js", "@aztec/noir-noirc_abi", "@aztec/bb.js"],
  },
});
