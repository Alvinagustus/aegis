import { defineConfig } from "vite";

// near-api-js / chainsig.js / wallet-selector dependency bundles were written
// for Node and reference `global` and `process.env`, which do not exist in the
// browser. Map them so the module graph loads instead of throwing.
export default defineConfig({
  define: {
    global: "globalThis",
    "process.env": {},
  },
  optimizeDeps: {
    esbuildOptions: {
      define: {
        global: "globalThis",
        "process.env": "{}",
      },
    },
  },
});
