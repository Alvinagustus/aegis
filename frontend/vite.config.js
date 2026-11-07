import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

// chainsig.js imports node's `crypto` (createHash only); give it a tiny browser shim.
const cryptoShim = fileURLToPath(new URL("./src/shims/crypto.js", import.meta.url));
const chainsigCrypto = {
  name: "chainsig-crypto-shim",
  enforce: "pre",
  resolveId(id, importer) {
    if (id === "crypto" && importer && importer.includes("chainsig.js")) return cryptoShim;
  },
};

// near-api-js / chainsig.js / wallet-selector dependency bundles were written
// for Node and reference `global` and `process.env`, which do not exist in the
// browser. Map them so the module graph loads instead of throwing.
export default defineConfig({
  plugins: [chainsigCrypto],
  define: {
    global: "globalThis",
    "process.env": {},
  },
  optimizeDeps: {
    exclude: [],
    esbuildOptions: {
      define: {
        global: "globalThis",
        "process.env": "{}",
      },
    },
  },
});
