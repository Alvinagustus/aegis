// Aegis dashboard — live window + wallet-connected deploy & operator actions
// (NEAR testnet). Write actions are signed by the connected NEAR wallet.
// The NEAR AI verdict step runs in the reviewer agent (API key must never
// reach the browser); MPC signing reuses chainsig.js with the wallet as
// the NEAR signer.
import { Buffer } from "buffer";
import { connect, Contract, keyStores, utils } from "near-api-js";
import { createPublicClient, http, formatEther } from "viem";
import { sepolia } from "viem/chains";
import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupModal } from "@near-wallet-selector/modal-ui";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { setupMyNearWallet } from "@near-wallet-selector/my-near-wallet";
import { setupNightly } from "@near-wallet-selector/nightly";
import { actionCreators } from "@near-js/transactions";
import "@near-wallet-selector/modal-ui/styles.css";

// Some NEAR dependency bundles expect the Node Buffer global.
if (!globalThis.Buffer) globalThis.Buffer = Buffer;

// Wallet Selector adapters (Meteor, Here, Sender, Narwallets) convert incoming
// actions with `najActionToInternal`, which expects near-api-js (NAJ) action
// objects (`{ functionCall: {...} }`). Passing the docs' `{ type, params }`
// shape makes them throw "Unsupported NAJ action".
const nearAction = (methodName, args, gas = 50_000_000_000_000n, deposit = 0n) =>
  actionCreators.functionCall(methodName, Buffer.from(JSON.stringify(args)), gas, deposit);

const eth = createPublicClient({ chain: sepolia, transport: http("https://ethereum-sepolia-rpc.publicnode.com") });

const CONTRACT = "watchdog-policy-4d8a7f.testnet";
const CONTRACT_V2 = "watchdog-v2-4d8a7f.testnet";
const MPC = "v1.signer-prod.testnet";
// Operator and the derived ETH address are NOT hardcoded (F13): operator is
// read from get_operator() of the active contract, and the ETH address is
// derived via Chain Signatures for that operator at runtime.
let OPERATOR = null;
let ETH_ADDRESS = null;

const signet = new contracts.ChainSignatureContract({ networkId: "testnet", contractId: MPC });
const evm = new chainAdapters.evm.EVM({ publicClient: eth, contract: signet });
async function deriveEthAddress(operator) {
  const { address } = await evm.deriveAddressAndPublicKey(operator, "ethereum-1");
  return address;
}

const KNOWN_VERDICTS = [
  { intent_hash: "0ff44a47472603f19687f365bc8a7d9b347cbc40", label: "0.001 ETH → whitelisted (chainsig demo)" },
  { intent_hash: "d74197c0abbe4d41a052b5f2e369afd2925a8583", label: "42 ETH seed-phrase phishing (denied)" },
  { intent_hash: "2fe970ebaaaea49cbf418f1c395b653fe31fc4da", label: "0.05 ETH freelancer payment" },
];

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const nearLink = (a) => `https://explorer.testnet.near.org/accounts/${a}`;
const row = (k, v) => `<tr><td class="k">${esc(k)}</td><td>${v}</td></tr>`;
const acct = (a) => `<a href="${nearLink(a)}" target="_blank" rel="noreferrer">${esc(a)}</a>`;
const pill = (text, kind = "neutral") => `<span class="pill ${kind}">${esc(text)}</span>`;
const statTile = (label, value) => `<div class="stat"><span class="stat-label">${esc(label)}</span><span class="stat-value">${value}</span></div>`;
const fmtEth = (wei) =>
  wei == null
    ? "—"
    : new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(Number(formatEther(BigInt(wei))));

// Contract timestamps are nanoseconds; older contracts omit some fields.
const fmtDuration = (ns, secondsPerUnit, unit) => {
  const value = ns == null ? NaN : Number(ns) / 1e9 / secondsPerUnit;
  return Number.isFinite(value) ? `${Number(value.toFixed(2))} ${unit}` : "—";
};

// ---- read-only near (views) ------------------------------------------------
// Views only need *an* on-chain account as the RPC context; the real
// operator is read from get_operator() below.
const near = await connect({ networkId: "testnet", keyStore: new keyStores.InMemoryKeyStore(), nodeUrl: "https://test.rpc.fastnear.com" });
const account = await near.account("watchdog-wallet-4d8a7f.testnet");
const VIEW_METHODS = ["get_operator", "get_policy", "get_reviewer", "get_guardians", "is_panicked", "get_ai_verdict", "get_hold", "simulate_tx", "is_whitelisted", "get_last_checkin", "get_heirs", "is_inheritance_open", "get_employees", "get_payroll_runs"];
let ACTIVE = localStorage.getItem("AEGIS_CONTRACT") || CONTRACT_V2;
let viewC = new Contract(account, ACTIVE, { viewMethods: VIEW_METHODS, changeMethods: [] });

// ---- wallet ---------------------------------------------------------------
let selector = null;
let wallet = null;
let currentIntent = null;

function currentAccount() {
  const accounts = selector?.store.getState().accounts || [];
  return accounts.find((a) => a.active) || accounts[0] || null;
}

function connectedAccount() {
  return currentAccount()?.accountId || null;
}

function renderWho() {
  const btn = document.getElementById("connect");
  const who = document.getElementById("who");
  const acc = currentAccount();
  if (acc) {
    const isOp = acc.accountId === OPERATOR;
    btn.textContent = "Disconnect";
    btn.classList.add("is-connected");
    btn.title = "Sign out of the connected NEAR wallet";
    who.innerHTML = `<span class="dot live"></span><a href="${nearLink(acc.accountId)}" target="_blank" rel="noreferrer">${esc(acc.accountId)}</a>${isOp ? pill("operator", "ok") : ""}`;
  } else {
    btn.textContent = "Connect NEAR wallet";
    btn.classList.remove("is-connected");
    btn.title = "Connect a NEAR wallet to sign transactions";
    who.innerHTML = `<span class="dot"></span>read-only mode`;
  }
}

async function syncWallet() {
  if (selector?.isSignedIn()) {
    try {
      wallet = await selector.wallet();
    } catch {
      wallet = null;
    }
  } else {
    wallet = null;
  }
  renderWho();
}

async function initWallet() {
  selector = await setupWalletSelector({
    network: "testnet",
    // Meteor/Sender hand apps a function-call key, so DeployContract is rejected.
    // MyNearWallet and Nightly sign with a full-access key, so in-app deploy works.
    modules: [
      setupMyNearWallet({ walletUrl: "https://testnet.mynearwallet.com" }),
      setupNightly(),
      setupMeteorWallet(),
    ],
  });
  const modal = setupModal(selector, { contractId: ACTIVE });
  const btn = document.getElementById("connect");

  btn.addEventListener("click", async () => {
    if (selector.isSignedIn()) {
      btn.disabled = true;
      try {
        const activeWallet = await selector.wallet();
        await activeWallet.signOut();
      } catch (err) {
        console.error("wallet sign-out failed", err);
      } finally {
        btn.disabled = false;
        await syncWallet();
      }
      return;
    }
    modal.show();
  });

  // Wallet selector emits "signedIn" / "signedOut" / "accountsChanged".
  selector.on("signedIn", () => syncWallet());
  selector.on("signedOut", () => syncWallet());
  selector.on("accountsChanged", () => syncWallet());

  // Meteor completes sign-in in a popup/tab, so re-sync when focus returns.
  window.addEventListener("focus", () => syncWallet());
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) syncWallet();
  });

  await syncWallet();
}

async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 40);
}

// ---- in-app deploy ----------------------------------------------------------
async function deployAegis({ contractAccount, fundNear, threshold }) {
  if (!wallet) throw new Error("connect a NEAR wallet first");
  const operator = connectedAccount();
  const out = document.getElementById("deploy-out");
  out.innerHTML = `fetching watchdog.wasm…`;
  const wasm = new Uint8Array(await (await fetch("/watchdog.wasm")).arrayBuffer());
  out.innerHTML = `sending ONE wallet transaction: create account + deploy code + init…<br/>
    <span class="hint">confirm in your wallet popup</span>`;
  const res = await wallet.signAndSendTransaction({
    signerId: operator,
    receiverId: contractAccount,
    actions: [
      actionCreators.createAccount(contractAccount),
      actionCreators.deployContract(wasm),
      actionCreators.functionCall(
        "new",
        Buffer.from(JSON.stringify({ operator, guard_threshold: Number(threshold) })),
        50_000_000_000_000n,
        0n
      ),
      // fund the new account with a real Transfer action (attachedDeposit is
      // not a wallet-selector parameter and gets ignored)
      actionCreators.transfer(BigInt(utils.format.parseNearAmount(String(fundNear)))),
    ],
  });
  out.innerHTML = `deployed ✓ tx: ${esc(res.transaction.hash)}<br/>switching active contract…`;
  switchActive(contractAccount);
}

// Meteor (and some other) wallets hand apps a function-call key, so they reject
// any DeployContract action. There is no browser-side workaround; print the exact
// CLI equivalent instead of a raw wallet error.
const WALLET_DEPLOY_BLOCK = /deploycontract|deploy contract|contract code|control of your account/i;

function deployBlockedHelp({ account, operator, threshold }) {
  const acct = account || "aegis.yourname.testnet";
  const op = operator || "yourname.testnet";
  const thr = Number(threshold) || 1;
  const create = `near create-account ${acct} --masterAccount ${op} --initialBalance 1`;
  const deploy = `near deploy ${acct} frontend/public/watchdog.wasm --initFunction new --initArgs '{"operator":"${op}","guard_threshold":${thr}}'`;
  return `<div class="notice warn"><b>${esc(account || "This wallet")} can’t deploy contracts from a dApp.</b>
    Meteor and Sender only grant function-call keys, so the page cannot bypass this. Two options:<br/>
    <b>1.</b> Disconnect, then connect with <b>MyNearWallet</b> (web, no extension) or <b>Nightly</b> — both sign with a
    full-access key, so “Create + deploy + init” works in this page.<br/>
    <b>2.</b> Deploy once from a terminal — your keys never enter the browser — then return here and use “Switch”.</div>
    <pre class="cmd"><code>${esc(create)}</code></pre>
    <pre class="cmd"><code>${esc(deploy)}</code></pre>
    <p class="hint">No CLI yet? <code>npm i -g near-cli</code> then <code>near login</code>. With near-cli-rs:
      <code>near contract deploy ${esc(acct)} use-file frontend/public/watchdog.wasm with-init-call new json-args '{"operator":"${esc(op)}","guard_threshold":${thr}}'</code>.</p>
    <button type="button" data-copy="${esc(`${create}\n${deploy}`)}">Copy commands</button>`;
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  try {
    await navigator.clipboard.writeText(btn.dataset.copy);
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = "Copy commands"), 1600);
  } catch {
    /* clipboard blocked: the commands stay selectable */
  }
});

document.getElementById("deploy-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const account = fd.get("account").trim();
  const threshold = fd.get("threshold").trim() || "1";
  try {
    await deployAegis({
      contractAccount: account,
      fundNear: fd.get("fund").trim() || "3",
      threshold,
    });
  } catch (err) {
    const msg = err?.message || String(err);
    const out = document.getElementById("deploy-out");
    out.innerHTML = WALLET_DEPLOY_BLOCK.test(msg)
      ? deployBlockedHelp({ account, operator: connectedAccount(), threshold })
      : `<span class="pill bad">deploy failed</span> <span class="mono">${esc(msg)}</span>`;
  }
});

document.getElementById("configure-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const reviewer = fd.get("reviewer").trim();
  const guardian = fd.get("guardian").trim();
  const out = document.getElementById("deploy-out");
  if (!wallet) return void (out.textContent = "connect a wallet first");
  const who = connectedAccount();
  const steps = [];
  if (reviewer) steps.push({ methodName: "set_reviewer", args: { reviewer } });
  if (guardian) steps.push({ methodName: "guardian_add", args: { account: guardian } });
  if (!steps.length) return void (out.textContent = "enter a reviewer and/or guardian");
  try {
    for (const s of steps) {
      out.innerHTML = `calling ${s.methodName}… (confirm in wallet)`;
      const res = await wallet.signAndSendTransaction({
        signerId: who,
        receiverId: ACTIVE,
        actions: [nearAction(s.methodName, s.args)],
      });
      out.innerHTML = `${s.methodName} ✓ ${esc(res?.transaction?.hash || "sent")}`;
    }
    await load();
  } catch (err) {
    out.innerHTML = `${pill("configure failed", "bad")} <span class="mono">${esc(err?.message || String(err))}</span>`;
  }
});

function switchActive(id) {
  ACTIVE = id;
  localStorage.setItem("AEGIS_CONTRACT", id);
  viewC = new Contract(account, ACTIVE, { viewMethods: VIEW_METHODS, changeMethods: [] });
  document.getElementById("active-contract").textContent = ACTIVE;
  load();
}

document.getElementById("switch-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const id = new FormData(e.target).get("contract").trim();
  if (id) switchActive(id);
});

// ---- transfer form ----------------------------------------------------------
document.getElementById("transfer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const chain = fd.get("chain").trim();
  const to = fd.get("to").trim();
  const amount = fd.get("amount").trim();
  const memo = fd.get("memo").trim();
  const ih = await sha256hex(`${chain}|${to.toLowerCase()}|${amount}|${memo}`);
  currentIntent = { chain, to, amount, memo, ih };
  const verdict = await viewC.get_ai_verdict({ intent_hash: ih }).catch(() => null);
  const sim = await viewC.simulate_tx({ chain, to, amount, intent_hash: ih }).catch(() => null);
  document.getElementById("transfer-out").innerHTML =
    `intent_hash: ${ih}<br/>verdict on-chain: ${verdict ? `risk ${verdict.risk} denied=${verdict.denied} (${esc(verdict.model)})` : "NONE — submit via reviewer agent first"}<br/>contract decision (simulate): <b>${sim ?? "?"}</b>`;
  const canSign = wallet && connectedAccount() === OPERATOR;
  const wl = document.getElementById("whitelist-address");
  if (wl && !wl.value.trim()) wl.value = to;
  document.getElementById("do-evaluate").disabled = !canSign;
  document.getElementById("do-sign").disabled = true;
});

document.getElementById("do-evaluate").addEventListener("click", async () => {
  const out = document.getElementById("transfer-out");
  if (!currentIntent) {
    out.innerHTML += "<br/>compute the intent hash first.";
    return;
  }
  out.innerHTML += "<br/>submitting to contract…";
  try {
    const res = await callContract("evaluate_tx", {
      chain: currentIntent.chain,
      to: currentIntent.to,
      amount: currentIntent.amount,
      intent_hash: currentIntent.ih,
    });
    out.innerHTML += `<br/>receipt: ${esc(res?.transaction?.hash || "sent")} — see explorer`;
    await load();
  } catch (err) {
    out.innerHTML += `<br/>${pill("evaluate failed", "bad")} <span class="mono">${esc(err?.message || String(err))}</span>`;
  }
});

document.getElementById("do-sign").addEventListener("click", async () => {
  document.getElementById("transfer-out").innerHTML += "<br/>MPC signing is done by the agent script: <code>node tools/chainsig/sign-eth.mjs</code> (same operator key).";
});

// ---- owner action buttons ----------------------------------------------------
async function callContract(method, args, deposit = "0", contractId = ACTIVE) {
  if (!wallet) throw new Error("Connect a NEAR wallet first (top-right button).");
  const signerId = connectedAccount();
  if (!signerId) throw new Error("Wallet reports no signed-in account — reconnect.");
  return wallet.signAndSendTransaction({
    signerId,
    receiverId: contractId,
    actions: [nearAction(method, args, 50_000_000_000_000n, BigInt(deposit))],
  });
}

function txOut(hash, label) {
  return hash
    ? `${pill(`${label} sent`, "ok")} <a href="https://testnet.nearblocks.io/txns/${encodeURIComponent(hash)}" target="_blank" rel="noreferrer" class="mono">${esc(hash)}</a>`
    : `${pill(`${label} sent`, "ok")} <span class="hint">wallet returned no hash (it may redirect to its own sign page) — check the explorer, then Refresh.</span>`;
}

async function ownerAction(btn, label, fn) {
  const out = document.getElementById("action-out");
  const prev = btn.textContent;
  btn.disabled = true;
  btn.textContent = `${label}…`;
  out.innerHTML = `<span class="hint">waiting for wallet signature…</span>`;
  try {
    const res = await fn();
    out.innerHTML = txOut(res?.transaction?.hash, label);
    await load();
  } catch (err) {
    out.innerHTML = `${pill(`${label} failed`, "bad")} <span class="mono">${esc(err?.message || String(err))}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = prev;
  }
}

document.getElementById("whitelist-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = document.getElementById("whitelist-address");
  const btn = document.getElementById("act-whitelist");
  const to = (input.value.trim() || currentIntent?.to || "");
  const out = document.getElementById("action-out");
  if (!to) {
    out.innerHTML = `${pill("whitelist failed", "bad")} <span class="mono">Enter the 0x… address to whitelist first.</span>`;
    input.focus();
    return;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(to)) {
    out.innerHTML = `${pill("whitelist failed", "bad")} <span class="mono">Not a valid EVM address: ${esc(to)}</span>`;
    input.focus();
    return;
  }
  ownerAction(btn, "whitelist", () => callContract("whitelist_add", { address: to }));
});

document.getElementById("act-checkin").addEventListener("click", (e) => {
  ownerAction(e.currentTarget, "check-in", () => callContract("check_in", {}));
});

document.getElementById("act-payroll").addEventListener("click", (e) => {
  ownerAction(e.currentTarget, "payroll", () => callContract("run_payroll", { chain: "eth" }));
});

document.getElementById("act-panicoff").addEventListener("click", (e) => {
  ownerAction(e.currentTarget, "panic_off", () => callContract("panic_off", {}));
});

// ---- dashboard render ----------------------------------------------------------
const safe = async (fn, fallback = null) => {
  try {
    return await fn();
  } catch {
    return fallback;
  }
};

// Scan hold ids (no list-view exists) for the first hold, or first capsule.
async function firstHold() {
  for (let id = 1; id <= 32; id++) {
    const h = await safe(() => viewC.get_hold({ id }));
    if (h) return { id, ...h };
  }
  return null;
}

async function load() {
  document.getElementById("active-contract").textContent = ACTIVE;
  OPERATOR = await safe(() => viewC.get_operator());
  ETH_ADDRESS = OPERATOR ? await safe(() => deriveEthAddress(OPERATOR)) : null;
  const [policy, reviewer, guardians, panicked, balance] = await Promise.all([
    safe(() => viewC.get_policy()),
    safe(() => viewC.get_reviewer()),
    safe(() => viewC.get_guardians(), []),
    safe(() => viewC.is_panicked()),
    ETH_ADDRESS ? eth.getBalance({ address: ETH_ADDRESS }) : 0n,
  ]);

  document.querySelector("#stats").innerHTML = [
    statTile("Panic mode", panicked ? pill("frozen", "bad") : pill("off", "ok")),
    statTile("Daily limit", policy ? `${fmtEth(policy.daily_limit)} ETH` : "—"),
    statTile("Guardian threshold", policy?.guard_threshold != null ? esc(String(policy.guard_threshold)) : "—"),
    statTile("Sepolia balance", balance != null ? `${Number(formatEther(balance)).toFixed(4)} ETH` : "—"),
  ].join("");

  document.querySelector("#accounts").innerHTML = [
    row("operator (wallet)", OPERATOR ? acct(OPERATOR) : "—"),
    row("contract", acct(ACTIVE)),
    row("AI reviewer", reviewer ? acct(reviewer) : "— (not set)"),
    row("guardians", guardians.map(acct).join("<br>") || "—"),
    row("panic mode", panicked ? pill("ACTIVE — all spending frozen", "bad") : pill("off", "ok")),
    row("MPC network", acct(MPC)),
  ].join("");

  document.querySelector("#policy").innerHTML = policy
    ? [
        row("daily limit (per chain)", `${fmtEth(policy.daily_limit)} ETH-equivalent`),
        row("quiet period (first-seen address)", fmtDuration(policy.quiet_period, 3600, "h")),
        row("guardian threshold", policy.guard_threshold ?? "—"),
        row("known-address grace", fmtDuration(policy.known_grace, 86400, "days")),
        row("panic cooldown", fmtDuration(policy.panic_cooldown, 3600, "h")),
        row("whitelisted demo address", esc("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")),
      ].join("")
    : row("—", "contract not initialized yet (deploy above)");

  const verdictRows = [];
  for (const v of KNOWN_VERDICTS) {
    const verdict = await safe(() => viewC.get_ai_verdict({ intent_hash: v.intent_hash }));
    if (!verdict) continue;
    const risky = verdict.denied || verdict.risk >= 70;
    verdictRows.push(row(v.label, `${pill(risky ? "DENY" : "pass", risky ? "bad" : "ok")} <span class="hint">risk ${verdict.risk}/100 · ${esc(verdict.model)}</span>`));
  }
  document.querySelector("#verdicts").innerHTML = verdictRows.join("") || row("—", "no verdicts yet");

  const hold = await firstHold();
  document.querySelector("#holds").innerHTML = hold
    ? [
        row(`hold #${hold.id}`, `${esc(hold.chain)} → ${esc(hold.to)} · amount ${esc(hold.amount)}`),
        row("status", esc(JSON.stringify(hold.status))),
        row("escalated by", (hold.escrow || []).map(acct).join("<br>") || "—"),
      ].join("")
    : row("—", "none");

  document.querySelector("#chainsig").innerHTML = [
    row("NEAR account", OPERATOR ? acct(OPERATOR) : "—"),
    row("derived ETH address", ETH_ADDRESS ? `<code>${ETH_ADDRESS}</code>` : "—"),
    row("Sepolia balance", `${formatEther(balance)} ETH`),
    row("proof of concept", `see README — Sepolia tx 0x2c24530d…eee507`),
  ].join("");

  // first capsule hold (capsule_release_at > 0), scanning ids from 1
  let capsule = null;
  for (let id = 1; id <= 32 && !capsule; id++) {
    const h = await safe(() => viewC.get_hold({ id }));
    if (h && h.capsule_release_at > 0) capsule = h;
  }
  document.querySelector("#capsule").innerHTML = capsule && capsule.capsule_release_at > 0
    ? [
        row("capsule", `${esc(capsule.chain)} → ${esc(capsule.to)} · amount ${esc(capsule.amount)} wei`),
        row("letter", `“${esc(capsule.message)}”`),
        row("opens at", new Date(Number(capsule.capsule_release_at) / 1e6).toISOString()),
        row("status", esc(String(capsule.status))),
      ].join("")
    : row("—", "none on this contract");

  const [lastCheckin, heirs, inheritanceOpen] = await Promise.all([
    safe(() => viewC.get_last_checkin()),
    safe(() => viewC.get_heirs(), []),
    safe(() => viewC.is_inheritance_open()),
  ]);
  document.querySelector("#inheritance").innerHTML = [
    row("last check-in", lastCheckin ? new Date(Number(lastCheckin) / 1e6).toISOString() : "—"),
    row("heirs", heirs.length ? heirs.map(esc).join("<br>") : "—"),
    row("state", inheritanceOpen ? pill("OPEN — heirs whitelisted", "ok") : pill("closed (owner active)", "neutral")),
  ].join("");

  const [employees, payrollRuns] = await Promise.all([
    safe(() => viewC.get_employees(), []),
    safe(() => viewC.get_payroll_runs()),
  ]);
  document.querySelector("#payroll").innerHTML = [
    row(
      "employees",
      employees.length
        ? employees.map((e) => `${esc(e.address)} — ${formatEther(BigInt(e.salary))} ETH/run`).join("<br>")
        : "—"
    ),
    row("payroll runs completed", String(payrollRuns ?? "—")),
  ].join("");
}

document.querySelector("#refresh").addEventListener("click", () => load().catch(console.error));
await initWallet().catch(console.error);
load().catch(console.error);

// Dev-only handle for poking at wallet state in the console.
if (import.meta.env.DEV) {
  window.__aegis = {
    get selector() {
      return selector;
    },
    syncWallet,
    renderWho,
    deployBlockedHelp,
  };
}
