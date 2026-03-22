import type { Plugin } from "vite";

/**
 * Shim Node.js built-in modules that shouldn't run in browser.
 * Must run before nodePolyfills to intercept fs/promises correctly.
 */
export const nodeBuiltinsShim = (): Plugin => ({
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
