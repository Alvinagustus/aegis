// Aegis relayer — builds an unsigned EIP-1559 transaction, submits it to the
// Aegis contract for policy-gated, contract-bound MPC signing (XCC), then
// assembles and broadcasts the signed transaction to Sepolia.
//
// The relayer is untrusted: it cannot choose a different recipient/amount than
// what the contract evaluates, because the contract decodes and binds `to` and
// `value` from `raw_tx_rlp` before signing.
//
// Flow:
//   1. (Optional) ensure an AI verdict exists on-chain for this intent.
//   2. Derive the EVM address from the Aegis contract account (path ethereum-1).
//   3. Build unsigned EIP-1559 tx (viem) and serialize to raw RLP bytes.
//   4. Call `evaluate_and_sign` on the Aegis contract (300 TGas + MPC deposit).
//   5. Extract MPC signature, assemble signed tx, broadcast to Sepolia.
//
// Env/config:
//   AEGIS_CONTRACT (default: aegis.testnet)
//   CALLER_ACCOUNT (default: aegis-operator.testnet, must be operator)
//   MPC_CONTRACT   (default: v1.signer-prod.testnet)
//   SEPOLIA_RPC    (default: https://ethereum-sepolia-rpc.publicnode.com)
//   PATH           (default: ethereum-1)
// Caller key is read from the near-cli keychain (never committed).

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { createPublicClient, http, parseEther, serializeTransaction, hexToBytes, bytesToHex } from "viem";
import { sepolia } from "viem/chains";
import { chainAdapters, contracts } from "chainsig.js";
import * as nearAPI from "near-api-js";

const AEGIS_CONTRACT = process.env.AEGIS_CONTRACT || "aegis.testnet";
const CALLER = process.env.CALLER_ACCOUNT || "aegis-operator.testnet";
const MPC = process.env.MPC_CONTRACT || "v1.signer-prod.testnet";
const DERIVATION_PATH = process.env.PATH || "ethereum-1";
const TO = process.argv[2] || "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
const AMOUNT_ETH = process.argv[3] || "0.001";
const SEPOLIA_RPC = process.env.SEPOLIA_RPC || "https://ethereum-sepolia-rpc.publicnode.com";
const MEMO = process.argv[4] || "aegis contract-bound demo";

function loadKeychain(accountId) {
  const dir = path.join(os.homedir(), ".near-credentials/testnet");
  const candidates = [path.join(dir, `${accountId}.json`), path.join(dir, accountId)];
  for (const p of candidates) {
    try {
      const stat = fs.statSync(p);
      if (stat.isDirectory()) {
        const file = fs.readdirSync(p).find((f) => f.startsWith("ed25519_") || f.endsWith(".json"));
        const j = JSON.parse(fs.readFileSync(path.join(p, file), "utf8"));
        return j.private_key;
      }
      const j = JSON.parse(fs.readFileSync(p, "utf8"));
      return j.private_key;
    } catch {}
  }
  throw new Error(`No key found for ${accountId} in ${dir}`);
}

function intentHash(chain, to, amount, memoHash, nonce) {
  const fields = [chain.toLowerCase(), to.toLowerCase()];
  const borsh = (str) => { const b = Buffer.from(str); const l = Buffer.alloc(4); l.writeUInt32LE(b.length); return Buffer.concat([l, b]); };
  const u128le = (v) => { const b = Buffer.alloc(16); const n = BigInt(v); b.writeBigUInt64LE(n & 0xffffffffffffffffn, 0); b.writeBigUInt64LE(n >> 64n, 8); return b; };
  const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
  const buf = Buffer.concat([borsh(fields[0]), borsh(fields[1]), u128le(amount), borsh(memoHash), u64le(nonce)]);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function toHex32(x) {
  let h = String(x || "").toLowerCase().replace(/^0x/, "");
  if (h.length > 64) h = h.slice(-64);
  return "0x" + h.padStart(64, "0");
}

function parseSignature(sig) {
  // MPC returns { big_r: { affine_point }, s: { scalar }, recovery_id }
  const rRaw = sig?.big_r?.affine_point ?? sig?.big_r ?? sig?.r;
  const sRaw = sig?.s?.scalar ?? sig?.s;
  const rec = sig?.recovery_id ?? sig?.v ?? 0;
  const r = toHex32(rRaw);
  const s = toHex32(sRaw);
  const yParity = Number(rec) % 2;
  return { r, s, yParity };
}

function getSuccessValue(outcome) {
  // near-api-js / RPC outcome shapes vary; try common locations.
  const status = outcome?.status || outcome?.transaction_outcome?.outcome?.status;
  if (status && typeof status.SuccessValue === "string") {
    const json = Buffer.from(status.SuccessValue, "base64").toString("utf8");
    try { return JSON.parse(json); } catch { return json; }
  }
  // receipts outcomes
  const receipts = outcome?.receipts_outcome || outcome?.receipts_outcome || [];
  for (let i = receipts.length - 1; i >= 0; i--) {
    const st = receipts[i]?.outcome?.status;
    if (st && typeof st.SuccessValue === "string") {
      const json = Buffer.from(st.SuccessValue, "base64").toString("utf8");
      try { return JSON.parse(json); } catch { return json; }
    }
  }
  return null;
}

const keyPair = nearAPI.KeyPair.fromString(loadKeychain(CALLER));
const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
await keyStore.setKey("testnet", CALLER, keyPair);
const NEAR_RPC = process.env.NEAR_RPC || "https://rpc.testnet.fastnear.com";
const near = await nearAPI.connect({ networkId: "testnet", keyStore, nodeUrl: NEAR_RPC });
const account = await near.account(CALLER);

const publicClient = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
const signet = new contracts.ChainSignatureContract({ networkId: "testnet", contractId: MPC });
const Evm = new chainAdapters.evm.EVM({ publicClient, contract: signet });

// 1) Derive EVM address from the Aegis contract account (contract-bound path).
const { address: fromAddress } = await Evm.deriveAddressAndPublicKey(AEGIS_CONTRACT, DERIVATION_PATH);
console.log("Aegis contract:", AEGIS_CONTRACT);
console.log("Derived ETH address (contract-bound):", fromAddress);

const amountWei = parseEther(AMOUNT_ETH).toString();
const memoHash = crypto.createHash("sha256").update(MEMO).digest("hex");
const nonceRaw = await account.viewFunction({ contractId: AEGIS_CONTRACT, methodName: "get_nonce", args: {} });
const nonce = Number(nonceRaw);
const ih = intentHash("eth", TO, amountWei, memoHash, nonce);
console.log("intent_hash:", ih);
console.log("nonce:", nonce);
console.log("Review command (run first if no verdict on-chain):");
console.log(`  node ../reviewer/review.mjs --submit '{"chain":"eth","to":"${TO}","amount":"${amountWei}","token":"ETH","memo":"${MEMO}"}'`);

// 2) Build unsigned EIP-1559 tx and serialize to RLP bytes.
const ethNonce = await publicClient.getTransactionCount({ address: fromAddress });
const fee = await publicClient.estimateFeesPerGas().catch(() => null);
const gas = await publicClient.estimateGas({ account: fromAddress, to: TO, value: parseEther(AMOUNT_ETH) }).catch(() => 21000n);
const tx = {
  type: "eip1559",
  chainId: sepolia.id,
  nonce: ethNonce,
  to: TO,
  value: parseEther(AMOUNT_ETH),
  gas,
  maxFeePerGas: fee?.maxFeePerGas ?? 2_000_000_000n,
  maxPriorityFeePerGas: fee?.maxPriorityFeePerGas ?? 1_000_000_000n,
};
const unsignedSerialized = serializeTransaction(tx); // 0x02... RLP
const rawTxRlp = Array.from(hexToBytes(unsignedSerialized));
console.log("Unsigned tx RLP bytes:", rawTxRlp.length);

// 3) Contract-bound evaluation + MPC signing (XCC).
const outcome = await account.functionCall({
  contractId: AEGIS_CONTRACT,
  methodName: "evaluate_and_sign",
  args: { chain: "eth", to: TO, amount: amountWei, memo_hash: memoHash, nonce, raw_tx_rlp: rawTxRlp, path: DERIVATION_PATH },
  gas: 300_000_000_000_000n,
  attachedDeposit: nearAPI.utils.format.parseNearAmount("0.05"),
});
const value = getSuccessValue(outcome);
console.log("evaluate_and_sign result:", JSON.stringify(value));

if (value === "Hold" || value === "Deny" || value == null) {
  console.log("Not approved/signed — refusing to broadcast.", value);
  process.exit(0);
}

// 4) Assemble signed tx and broadcast.
const sig = parseSignature(value);
console.log("MPC signature parsed (r/s/yParity):", { r: sig.r.slice(0, 18) + "…", s: sig.s.slice(0, 18) + "…", yParity: sig.yParity });
const signedTx = serializeTransaction(tx, sig);
console.log("Signed tx:", signedTx.slice(0, 66) + "…");
try {
  const hash = await publicClient.sendRawTransaction({ serializedTransaction: signedTx });
  console.log("Broadcast on Sepolia:", hash);
  console.log("Explorer: https://sepolia.etherscan.io/tx/" + hash);
} catch (e) {
  console.log("Broadcast failed:", String(e?.message || e).slice(0, 240));
  console.log("Signed tx (hex) available above for manual relay.");
}
