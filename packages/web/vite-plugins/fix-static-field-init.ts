import type { Plugin } from "vite";

/**
 * Fix static class field initialization issue with Rollup bundling.
 * Rollup transforms `class Foo {}` to `let Foo; Foo = class {}` which breaks
 * static initializers like `static ZERO = new AztecAddress(...)`.
 * This plugin patches the minified output with a lazy getter.
 */
export const fixStaticFieldInit = (): Plugin => ({
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
