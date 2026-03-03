import react from "@vitejs/plugin-react";
import { defineConfig, Plugin } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";

/**
 * Fix static class field initialization issue with Rollup bundling.
 * Rollup transforms `class Foo {}` to `let Foo; Foo = class {}` which breaks
 * static initializers like `static ZERO = new AztecAddress(...)`.
 * This plugin patches the minified output with a lazy getter.
 */
const fixStaticFieldInit = (): Plugin => ({
  name: "fix-static-field-init",
  enforce: "post",
  async writeBundle(options, bundle) {
    const fs = await import("fs");
    const path = await import("path");
    const outDir = options.dir || "dist";

    for (const [fileName, chunk] of Object.entries(bundle)) {
      if (chunk.type === "chunk" && fileName.endsWith(".js")) {
        const filePath = path.default.join(outDir, fileName);
        let code = fs.default.readFileSync(filePath, "utf-8");

        const pattern = /static ZERO=new (\w+)\((\w+)\.alloc\(32,0\)\)/g;
        if (pattern.test(code)) {
          code = code.replace(
            /static ZERO=new (\w+)\((\w+)\.alloc\(32,0\)\)/g,
            "static get ZERO(){return this._ZC||(this._ZC=new $1($2.alloc(32,0)))}",
          );
          fs.default.writeFileSync(filePath, code);
          console.log(`[fix-static-field-init] Patched ${fileName}`);
        }
      }
    }
  },
});

/**
 * Shim Node.js built-in modules that shouldn't run in browser.
 * Must run before nodePolyfills to intercept fs/promises correctly.
 */
const nodeBuiltinsShim = (): Plugin => ({
  name: "node-builtins-shim",
  enforce: "pre",
  resolveId(source) {
    if (["fs/promises", "fs", "net", "tty"].includes(source)) {
      return `\0virtual:${source}`;
    }
    return null;
  },
  load(id) {
    if (id === "\0virtual:fs/promises") {
      return `
        export const mkdir = () => Promise.reject(new Error('fs/promises not available in browser'));
        export const writeFile = () => Promise.reject(new Error('fs/promises not available in browser'));
        export const readFile = () => Promise.reject(new Error('fs/promises not available in browser'));
        export const rm = () => Promise.reject(new Error('fs/promises not available in browser'));
        export default { mkdir, writeFile, readFile, rm };
      `;
    }
    if (id === "\0virtual:fs") {
      return `
        export const existsSync = () => false;
        export const readFileSync = () => { throw new Error('fs not available in browser'); };
        export const writeFileSync = () => { throw new Error('fs not available in browser'); };
        export const mkdirSync = () => { throw new Error('fs not available in browser'); };
        export default { existsSync, readFileSync, writeFileSync, mkdirSync };
      `;
    }
    if (id === "\0virtual:net") {
      return `
        export const Socket = class Socket { constructor() { throw new Error('net not available in browser'); } };
        export const connect = () => { throw new Error('net not available in browser'); };
        export default { Socket, connect };
      `;
    }
    if (id === "\0virtual:tty") {
      return `
        export const isatty = () => false;
        export default { isatty };
      `;
    }
    return null;
  },
});

export default defineConfig({
  plugins: [
    nodeBuiltinsShim(), // Must be first to intercept before nodePolyfills
    react(),
    wasm(),
    topLevelAwait(),
    fixStaticFieldInit(),
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
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      exclude: ["fs", "net", "tty"],
    }),
  ],
  assetsInclude: ["**/*.wasm"],
  define: {
    global: "globalThis",
  },
  worker: {
    format: "es",
  },
  esbuild: {
    target: "esnext",
  },
  resolve: {
    alias: {
      crypto: "crypto-browserify",
      stream: "stream-browserify",
      util: "util",
      path: "path-browserify",
      pino: "pino/browser.js",
      "hash.js": "hash.js/lib/hash.js",
      sha3: "sha3/index.js",
      "lodash.chunk": "lodash.chunk/index.js",
      "lodash.times": "lodash.times/index.js",
      "lodash.isequal": "lodash.isequal/index.js",
      "lodash.pickby": "lodash.pickby/index.js",
      "json-stringify-deterministic":
        "json-stringify-deterministic/lib/index.js",
    },
  },
  server: {
    port: 3001,
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "credentialless",
      "Cross-Origin-Resource-Policy": "cross-origin",
    },
    fs: {
      allow: [".."],
    },
  },
  preview: {
    port: 3001,
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "credentialless",
      "Cross-Origin-Resource-Policy": "cross-origin",
    },
  },
  build: {
    sourcemap: false,
    minify: "esbuild",
    chunkSizeWarningLimit: 2000,
    target: "esnext",
    commonjsOptions: {
      defaultIsModuleExports: (id: string) => {
        if (id.includes("@aztec/")) return false;
        return "auto";
      },
      exclude: [
        "@aztec/stdlib/**",
        "@aztec/foundation/**",
        "@aztec/aztec.js/**",
      ],
    },
    rollupOptions: {
      output: {
        format: "es",
        preserveModules: false,
        inlineDynamicImports: false,
        interop: "auto",
      },
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
    exclude: ["@aztec/noir-acvm_js", "@aztec/noir-noirc_abi", "@aztec/bb.js"],
    esbuildOptions: {
      define: {
        global: "globalThis",
      },
    },
  },
});
