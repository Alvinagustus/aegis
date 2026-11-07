// Watchdog AI reviewer — classifies a transfer intent with a model running
// inside NEAR AI Cloud's TEE, then attests the verdict on-chain
// (watchdog.submit_verdict). Verdict risk: 0 = safe … 100 = malicious.
//
// Env (see ../../.env.example):
//   NEAR_AI_API_KEY    — NEAR AI Cloud key
//   REVIEW_MODEL       — model id (default Qwen/Qwen3.8-27B)
//   WATCHDOG_CONTRACT  — e.g. watchdog-alice.testnet
//   REVIEWER_ACCOUNT   — the reviewer account appointed in the contract
//   REVIEWER_KEY       — private key (ed25519:...) of REVIEWER_ACCOUNT
//
// Usage:
//   node review.mjs '{"chain":"eth","to":"0x...","amount":"1000000000000000000","memo":"payment"}'
//   node review.mjs --submit '...'   # also attest on-chain (needs reviewer key)

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import * as nearAPI from "near-api-js";

const CONTRACT_ID_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

function loadEnv() {
  const envFile = path.resolve(import.meta.dirname, "../../.env");
  for (const line of fs.existsSync(envFile) ? fs.readFileSync(envFile, "utf8").split("\n") : []) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
}

const SYSTEM_PROMPT = `You are the on-chain spending risk reviewer for Aegis, a non-custodial policy engine guarding NEAR-controlled wallets on Bitcoin and Ethereum.

Score the RISK of the requested outbound transfer. Consider:
- The destination address format and plausibility (EVM address, BTC address, internal-account names).
- Known scam patterns: drain-aizer, address-poisoning-prefix lookalikes, approval-rug phrasing, urgency or emotional manipulation in the memo.
- Amount anomalies relative to the stated memo (e.g. "one-time small payment" of 50 ETH).
- Refusal to explain or memos with suspicious obfuscation (base64 blobs, unicode tricks).

You cannot see balances or history; judge only on the given context.

Answer with ONLY a JSON object, no markdown, no prose:
{"risk": <0-100>, "denied": <true|false>, "reason": "<one tight sentence>"}
Guidance: 0-39 benign, 40-69 suspicious (needs a second look), 70+ malicious (denied=true).`

async function askModel(intent) {
  const key = process.env.NEAR_AI_API_KEY;
  if (!key) throw new Error("NEAR_AI_API_KEY missing (put it in ../.env)");
  const model = process.env.REVIEW_MODEL || "Qwen/Qwen3.8-27B";

  const res = await fetch("https://cloud-api.near.ai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        {
          role: "user",
          content: `Chain: ${intent.chain}\nDestination: ${intent.to}\nAmount: ${intent.amount}\nToken: ${intent.token || "native"}\nMemo: ${intent.memo || "(none)"}`,
        },
      ],
      temperature: 0,
      max_tokens: 400,
    }),
  });
  if (!res.ok) throw new Error(`NEAR AI ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return { model: data.model ?? model, text: data.choices?.[0]?.message?.content ?? "" };
}

async function askModelWithRetry(intent) {
  let lastErr;
  const attempts = 3;
  for (let i = 1; i <= attempts; i++) {
    try {
      const r = await askModel(intent);
      parseVerdict(r.text); // validate BEFORE using
      return r;
    } catch (e) {
      lastErr = e;
      console.error(`attempt ${i} failed: ${e.message}; retrying…`);
    }
  }
  // Fail CLOSED after retries: worst-case verdict, never submit a pass.
  console.error(`⚠️ model failed ${attempts} times — submitting fail-closed verdict (risk=100, denied=true)`);
  return { model: process.env.REVIEW_MODEL || "Qwen/Qwen3.8-27B", text: '{"risk":100,"denied":true,"reason":"reviewer unavailable"}' };
}

function parseVerdict(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error(`no JSON in model response: ${text.slice(0, 200)}`);
  let v;
  try {
    v = JSON.parse(text.slice(start, end + 1));
  } catch {
    throw new Error(`unparseable model response: ${text.slice(0, 200)}`);
  }
  // Fail CLOSED: strict types only — no coercion. A malformed reply is an
  // error (caller retries, then escalates to risk=100/denied=true).
  if (!Number.isInteger(v.risk) || v.risk < 0 || v.risk > 100)
    throw new Error(`risk out of range or non-integer: ${JSON.stringify(v.risk)}`);
  if (typeof v.denied !== "boolean")
    throw new Error(`denied must be boolean: ${JSON.stringify(v.denied)}`);
  return { risk: v.risk, denied: v.denied, reason: String(v.reason ?? "") };
}

export function intentHash(intent, nonce) {
  // Must match the contract's compute_intent_hash:
  // sha256("chain|to_lower|amount|memo_hash|nonce") with memo_hash = sha256(memo)
  const memoHash = crypto.createHash("sha256").update(intent.memo || "").digest("hex");
  return (
    intent.intent_hash ||
    crypto.createHash("sha256").update(`${intent.chain}|${intent.to.toLowerCase()}|${intent.amount}|${memoHash}|${nonce ?? 0}`).digest("hex")
  );
}

async function submitOnChain({ intentHash, risk, denied, model }) {
  for (const k of ["WATCHDOG_CONTRACT", "REVIEWER_ACCOUNT", "REVIEWER_KEY"]) {
    if (!process.env[k] || k === "WATCHDOG_CONTRACT" && !CONTRACT_ID_RE.test(process.env[k])) throw new Error(`${k} missing/invalid`);
  }
  const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
  await keyStore.setKey("testnet", process.env.REVIEWER_ACCOUNT, nearAPI.KeyPair.fromString(process.env.REVIEWER_KEY));
  const near = await nearAPI.connect({
    networkId: "testnet",
    keyStore,
    nodeUrl: "https://testnet-rpc.intea.rs",
  });
  const account = await near.account(process.env.REVIEWER_ACCOUNT);
  const result = await account.functionCall({
    contractId: process.env.WATCHDOG_CONTRACT,
    methodName: "submit_verdict",
    args: { intent_hash: intentHash, risk, denied, model },
    gas: 50_000_000_000_000n,
  });
  return result?.transaction?.hash ?? "ok";
}

const intentArg = process.argv[process.argv.length - 2] === "--submit" ? process.argv[process.argv.length - 1] : process.argv[process.argv.length - 1];
const doSubmit = process.argv.includes("--submit");
const intent = JSON.parse(intentArg);

loadEnv();
const { model, text } = await askModelWithRetry(intent);
const verdict = parseVerdict(text);

// The verdict key depends on the contract nonce (F3): fetch it from chain.
let nonce = 0;
if (process.env.WATCHDOG_CONTRACT && process.env.REVIEWER_ACCOUNT && process.env.REVIEWER_KEY) {
  try {
    const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
    await keyStore.setKey("testnet", process.env.REVIEWER_ACCOUNT, nearAPI.KeyPair.fromString(process.env.REVIEWER_KEY));
    const near = await nearAPI.connect({ networkId: "testnet", keyStore, nodeUrl: "https://testnet-rpc.intea.rs" });
    nonce = Number(await near.account(process.env.REVIEWER_ACCOUNT).viewFunction({ contractId: process.env.WATCHDOG_CONTRACT, methodName: "get_nonce", args: {} }));
  } catch (e) {
    console.error("could not read get_nonce (using 0):", e.message);
  }
}
const ih = intentHash(intent, nonce);
const out = {
  intent_hash: ih,
  nonce,
  chain: intent.chain,
  to: intent.to,
  amount: intent.amount,
  risk: verdict.risk,
  denied: verdict.denied,
  reason: verdict.reason,
  model,
};
console.log(JSON.stringify(out, null, 2));

if (doSubmit) {
  const txHash = await submitOnChain({ intentHash: ih, risk: verdict.risk, denied: verdict.denied, model });
  console.log(JSON.stringify({ on_chain: "submit_verdict", tx: txHash }, null, 2));
}
