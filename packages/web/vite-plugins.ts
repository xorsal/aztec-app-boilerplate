import type { Plugin } from "vite";

// ── Cross-Origin headers (required for SharedArrayBuffer / WASM crypto) ──

export const CROSS_ORIGIN_HEADERS: Record<string, string> = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "credentialless",
  "Cross-Origin-Resource-Policy": "cross-origin",
};

// ── CJS packages with broken ESM resolution ──

export const CJS_ALIASES: Record<string, string> = {
  pino: "pino/browser.js",
  "hash.js": "hash.js/lib/hash.js",
  sha3: "sha3/index.js",
  "lodash.chunk": "lodash.chunk/index.js",
  "lodash.times": "lodash.times/index.js",
  "lodash.isequal": "lodash.isequal/index.js",
  "lodash.pickby": "lodash.pickby/index.js",
  "json-stringify-deterministic": "json-stringify-deterministic/lib/index.js",
};

// ── Aztec packages excluded from esbuild pre-bundling ──
// They use WASM + top-level await — incompatible with esbuild.

export const AZTEC_EXCLUDED = [
  "bb.js",
  "pxe",
  "pxe/client/lazy",
  "foundation",
  "circuits.js",
  "noir-contracts.js",
  "noir-acvm_js",
  "noir-noirc_abi",
  "accounts",
  "stdlib",
  "aztec.js",
  "entrypoints",
  "wallets",
  "l1-artifacts",
  "protocol-contracts",
]
  .map((p) => `@aztec/${p}`)
  .concat(["@aztec-app/eip712", "@aztec-app/contracts"]);

// ── Node built-in shims ──
// Stub modules that leak from Aztec SDK server-side code paths.
// Must run before nodePolyfills so these are intercepted first.

const NODE_SHIMS: Record<string, string> = {
  fs: `export const existsSync = () => false; export default { existsSync };`,
  "fs/promises": `const noop = () => Promise.resolve(); export const mkdir = noop; export const writeFile = noop; export const readFile = noop; export const rm = noop; export default { mkdir, writeFile, readFile, rm };`,
  net: `export const Socket = class {}; export const connect = () => {}; export default { Socket, connect };`,
  tty: `export const isatty = () => false; export default { isatty };`,
};

export const nodeBuiltinsShim = (): Plugin => ({
  name: "node-builtins-shim",
  enforce: "pre",
  resolveId: (id) => (id in NODE_SHIMS ? `\0shim:${id}` : null),
  load: (id) => (id.startsWith("\0shim:") ? NODE_SHIMS[id.slice(6)] : null),
});

// ── Rollup static self-reference fix (production builds only) ──
//
// Rollup hoists classes:  class Fr { static ZERO = new Fr(0n) }
//                     →   Fr = class { static ZERO = new Fr(0n) }   // Fr undefined!
//
// We patch these into lazy getters that defer until the class is assigned.

export const fixStaticSelfRef = (): Plugin => ({
  name: "fix-static-self-ref",
  enforce: "post",
  async writeBundle(options, bundle) {
    const fs = await import("fs");
    const path = await import("path");
    const outDir = options.dir || "dist";

    for (const [fileName, chunk] of Object.entries(bundle)) {
      if (chunk.type !== "chunk" || !fileName.endsWith(".js")) continue;

      const filePath = path.default.join(outDir, fileName);
      let code = fs.default.readFileSync(filePath, "utf-8");

      // Find hoisted class names: "Fr = class" pattern
      const classNames = new Set<string>();
      for (const m of code.matchAll(/(\w+)\s*=\s*class\b/g)) {
        classNames.add(m[1]);
      }
      if (classNames.size === 0) continue;

      let patched = false;
      for (const cls of classNames) {
        const re = new RegExp(
          `static\\s+(\\w+)\\s*=\\s*new\\s+${cls}\\(`,
          "g",
        );
        let m;
        while ((m = re.exec(code)) !== null) {
          const prop = m[1];
          const argsStart = m.index + m[0].length;
          let depth = 1;
          let i = argsStart;
          while (i < code.length && depth > 0) {
            if (code[i] === "(") depth++;
            else if (code[i] === ")") depth--;
            i++;
          }
          if (depth !== 0) continue;

          const args = code.slice(argsStart, i - 1);
          const getter = `static get ${prop}(){return this.__${prop}??(this.__${prop}=new ${cls}(${args}))}`;
          code = code.slice(0, m.index) + getter + code.slice(i);
          patched = true;
          re.lastIndex = m.index + getter.length;
        }
      }

      if (patched) {
        fs.default.writeFileSync(filePath, code);
        console.log(`[fix-static-self-ref] Patched ${fileName}`);
      }
    }
  },
});
