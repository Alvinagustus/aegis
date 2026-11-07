// Minimal browser stand-in for node:crypto — chainsig.js only needs createHash().
import { Buffer } from "buffer";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";

const algos = { sha256, sha512, ripemd160 };
export function createHash(name) {
  const fn = algos[name];
  if (!fn) throw new Error(`createHash(${name}) is not supported in the browser build`);
  const chunks = [];
  const api = {
    update(data) { chunks.push(typeof data === "string" ? Buffer.from(data) : Buffer.from(data)); return api; },
    digest() { return Buffer.from(fn(Buffer.concat(chunks))); },
  };
  return api;
}
export default { createHash };
