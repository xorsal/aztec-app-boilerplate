import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import {
  AZTEC_EXCLUDED,
  CJS_ALIASES,
  CROSS_ORIGIN_HEADERS,
  fixStaticSelfRef,
  nodeBuiltinsShim,
} from "./vite-plugins";

export default defineConfig({
  plugins: [
    nodeBuiltinsShim(),
    react(),
    fixStaticSelfRef(),
    nodePolyfills({
      include: [
        "buffer",
        "crypto",
        "util",
        "assert",
        "process",
        "stream",
        "path",
        "events",
      ],
      globals: { Buffer: true, global: true, process: true },
      exclude: ["fs", "net", "tty"],
    }),
  ],
  assetsInclude: ["**/*.wasm"],
  define: { global: "globalThis" },
  worker: { format: "es" },
  esbuild: { target: "esnext" },
  resolve: { alias: CJS_ALIASES },
  server: {
    port: 3001,
    headers: CROSS_ORIGIN_HEADERS,
    fs: { allow: ["../.."] },
  },
  preview: {
    port: 3001,
    headers: CROSS_ORIGIN_HEADERS,
  },
  build: {
    sourcemap: false,
    minify: "esbuild",
    chunkSizeWarningLimit: 2000,
    target: "esnext",
    commonjsOptions: {
      defaultIsModuleExports: (id: string) =>
        id.includes("@aztec/") ? false : "auto",
      exclude: [
        "@aztec/stdlib/**",
        "@aztec/foundation/**",
        "@aztec/aztec.js/**",
      ],
    },
  },
  optimizeDeps: {
    include: [
      "react",
      "react-dom",
      "react/jsx-runtime",
      "buffer",
      "crypto-browserify",
      "stream-browserify",
      "util",
    ],
    exclude: AZTEC_EXCLUDED,
    esbuildOptions: { define: { global: "globalThis" } },
  },
});
