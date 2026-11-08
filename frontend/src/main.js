// Aegis dashboard — live window + wallet-connected owner/guardian actions (NEAR testnet).
// Write actions are signed by the connected NEAR wallet. The NEAR AI verdict step runs in the
// reviewer agent and MPC signing in tools/chainsig (keys and API keys never reach the browser).
// Add ?demo (or ?demo=ok) to the URL to explore the UI against an in-memory mock.
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

// Wallet Selector adapters expect near-api-js (NAJ) action objects, not `{ type, params }`.
const nearAction = (methodName, args, gas = 50_000_000_000_000n, deposit = 0n) =>
  actionCreators.functionCall(methodName, Buffer.from(JSON.stringify(args)), gas, deposit);

// ───────────────── constants ─────────────────
const params = new URLSearchParams(location.search);
const DEMO = params.has("demo");
const MPC = "v1.signer-prod.testnet";
// Candidate contracts probed after a wallet connects. A candidate is only ever selected when the
// connected wallet is its operator or one of its guardians, so other visitors never see it.
const KNOWN_DEPLOYMENTS = ["aegispolicy.testnet"];
const ETH_PATH = "ethereum-1";
const SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com";
const NODE_URL = "https://test.rpc.fastnear.com";
const ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const STORAGE_BYTE_COST = 10n ** 19n; // yoctoNEAR per stored byte
const HOLD_SCAN_LIMIT = 15;
const ADMIN_DAY_NS = "86400000000000"; // 1 day, the production admin timelock


// ───────────────── helpers ─────────────────
const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nearLink = (a) => `https://explorer.testnet.near.org/accounts/${encodeURIComponent(a)}`;
const row = (k, v) => `<tr><td class="k">${esc(k)}</td><td>${v}</td></tr>`;
const acct = (a) => `<a href="${nearLink(a)}" target="_blank" rel="noreferrer">${esc(a)}</a>`;
const pill = (text, kind = "neutral") => `<span class="pill ${kind}">${esc(text)}</span>`;
const statTile = (label, value, sub = "") =>
  `<div class="stat"><span class="stat-label">${esc(label)}</span><span class="stat-value">${value}</span>${sub ? `<span class="stat-sub">${sub}</span>` : ""}</div>`;
const errMsg = (e) => String(e?.message || e || "Unknown error").slice(0, 240);
const txHash = (res) => res?.transaction?.hash ?? res?.transaction_outcome?.id ?? "";
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } },
};

const activeKey = (acc) => `AEGIS_CONTRACT_${acc}`;
function myDeploysKey(acc) { return `AEGIS_MY_DEPLOY_${acc}`; }
function getMyDeploys(acc) {
  if (!acc) return [];
  try { return JSON.parse(store.get(myDeploysKey(acc)) || "[]"); } catch { return []; }
}
function rememberDeploy(acc, contractId) {
  if (!acc || !contractId) return;
  const list = getMyDeploys(acc);
  if (!list.includes(contractId)) {
    list.unshift(contractId);
    store.set(myDeploysKey(acc), JSON.stringify(list.slice(0, 20)));
  }
}

function fmtEth(wei) {
  if (wei == null) return "—";
  let n;
  try { n = Number(formatEther(BigInt(wei))); } catch { return "—"; }
  if (n === 0) return "0";
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: n >= 1 ? 2 : 6 }).format(n);
}
// Contract timestamps / durations are nanoseconds.
function fmtNs(ns) {
  const v = Number(ns);
  if (!Number.isFinite(v)) return "—";
  const s = v / 1e9;
  if (s < 1) return `${v} ns`;
  if (s < 120) return `${+s.toFixed(1)} s`;
  if (s < 7200) return `${+(s / 60).toFixed(1)} min`;
  if (s < 172800) return `${+(s / 3600).toFixed(1)} h`;
  return `${+(s / 86400).toFixed(1)} days`;
}
const fmtDate = (ns) => (Number(ns) > 0 ? new Date(Number(ns) / 1e6).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "—");

function toast(title, { detail = "", tx = "", kind = "info" } = {}) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<b>${esc(title)}</b>${detail ? `<span>${esc(detail)}</span>` : ""}${
    tx ? `<span><a href="https://testnet.nearblocks.io/txns/${encodeURIComponent(tx)}" target="_blank" rel="noreferrer">View transaction ${esc(String(tx).slice(0, 10))}…</a></span>` : ""}`;
  $("toasts").appendChild(el);
  setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 300); }, kind === "bad" ? 9000 : 5500);
}
async function busy(btn, label, fn) {
  const prev = btn?.textContent;
  if (btn) { btn.disabled = true; btn.classList.add("is-busy"); if (label) btn.textContent = label; }
  try { return await fn(); }
  finally { if (btn?.isConnected) { btn.classList.remove("is-busy"); btn.textContent = prev; applyRoles(); } }
}
const safe = async (fn, fallback = null) => { try { return await fn(); } catch { return fallback; } };
async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ───────────────── state ─────────────────
// Nothing is shown until a wallet connects: no default contract, no author accounts.
// The active contract is remembered per connected account, never globally.
let ACTIVE = DEMO ? "aegis-demo.testnet" : null;
let lastAccount = null;
let selector = null;
let wallet = null;
let modal = null;
let viewC = null;
let demo = null;
let eth = null;
let currentIntent = null;
const S = { operator: null, guardians: [], policy: null, reviewer: null, panicked: false, ethAddress: null };
const ethCache = new Map();

// ───────────────── chain access ─────────────────
async function initView() {
  if (DEMO) {
    const { createDemo } = await import("./demo.js");
    demo = createDemo({ healthy: params.get("demo") === "ok" });
    viewC = demo.viewC;
    eth = { getBalance: async () => demo.ethBalance };
    return;
  }
  eth = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
  const near = await connect({ networkId: "testnet", keyStore: new keyStores.InMemoryKeyStore(), nodeUrl: NODE_URL });
  window.__nearAccount = await near.account(MPC); // only the caller identity for view calls
  makeView();
}
const VIEW_METHODS = ["get_operator", "get_policy", "get_reviewer", "get_guardians", "is_panicked", "get_ai_verdict", "get_hold", "simulate_tx", "is_whitelisted", "get_nonce", "compute_intent_hash", "get_last_checkin", "get_heirs", "is_inheritance_open", "get_employees", "get_payroll_runs", "get_admin_proposals", "get_admin_delay"];
function makeView() {
  if (DEMO) return;
  viewC = ACTIVE && window.__nearAccount ? new Contract(window.__nearAccount, ACTIVE, { viewMethods: VIEW_METHODS, changeMethods: [] }) : null;
}

async function deriveEthAddress(operator) {
  if (!operator) return null;
  if (DEMO) return demo.ethAddress;
  if (ethCache.has(operator)) return ethCache.get(operator);
  let address = null;
  try {
    const { chainAdapters, contracts } = await import("chainsig.js");
    const signet = new contracts.ChainSignatureContract({ networkId: "testnet", contractId: MPC });
    const Evm = new chainAdapters.evm.EVM({ publicClient: eth, contract: signet });
    ({ address } = await Evm.deriveAddressAndPublicKey(operator, ETH_PATH));
  } catch (err) {
    console.warn("chainsig derive failed", err);
    address = null;
  }
  ethCache.set(operator, address);
  return address;
}

// ───────────────── wallet ─────────────────
function currentAccount() {
  if (DEMO) return { accountId: demo.me, active: true };
  const accounts = selector?.store.getState().accounts || [];
  return accounts.find((a) => a.active) || accounts[0] || null;
}
const connectedAccount = () => currentAccount()?.accountId || null;
const isOperator = () => !!S.operator && connectedAccount() === S.operator;
const isGuardian = () => S.guardians.includes(connectedAccount());

function renderWho() {
  const btn = $("connect");
  const acc = currentAccount();
  if (acc) {
    btn.textContent = DEMO ? "Demo mode" : "Disconnect";
    btn.classList.add("is-connected");
    $("who").innerHTML = `<span class="dot live"></span><a href="${nearLink(acc.accountId)}" target="_blank" rel="noreferrer" title="${esc(acc.accountId)}">${esc(acc.accountId)}</a>`;
  } else {
    btn.textContent = "Connect wallet";
    btn.classList.remove("is-connected");
    $("who").innerHTML = `<span class="dot"></span>Read-only`;
  }
  $("roles").innerHTML = (isOperator() ? pill("operator", "ok") : "") + (isGuardian() ? pill("guardian", "info") : "");
}

// Buttons marked data-role are only usable by that role; the title explains why.
function applyRoles() {
  const has = { operator: isOperator(), guardian: isGuardian() };
  document.querySelectorAll("[data-role]").forEach((b) => {
    if (b.classList.contains("is-busy")) return;
    const ok = has[b.dataset.role];
    b.disabled = !ok;
    b.title = ok ? "" : connectedAccount() ? `Only the ${b.dataset.role} of this contract can do this` : "Connect a wallet first";
  });
  const evalBtn = $("do-evaluate");
  if (evalBtn) {
    evalBtn.disabled = !(isOperator() && currentIntent);
    $("evaluate-hint").textContent = !connectedAccount()
      ? "Connect the operator wallet to submit."
      : !isOperator() ? `Connected as ${connectedAccount()}, but the operator of this contract is ${S.operator ?? "unknown"}.` : "";
  }
}

// Does `me` run this contract (operator or guardian)? Read-only view calls, no wallet needed.
async function roleIn(contractId, me) {
  if (!window.__nearAccount) return null;
  const c = new Contract(window.__nearAccount, contractId, { viewMethods: ["get_operator", "get_guardians"], changeMethods: [] });
  const op = await safe(() => c.get_operator());
  if (!op) return null;
  if (op === me) return "operator";
  const guardians = await safe(() => c.get_guardians(), []);
  return (guardians || []).includes(me) ? "guardian" : null;
}

async function resolveActive() {
  if (DEMO) return;
  const me = connectedAccount();
  if (!me) { ACTIVE = null; return; }
  const saved = store.get(activeKey(me));
  if (saved && ACCOUNT_RE.test(saved)) { ACTIVE = saved; return; }
  const mine = getMyDeploys(me);
  const candidates = [...new Set([...mine, `aegis.${me}`, ...KNOWN_DEPLOYMENTS])].filter((c) => ACCOUNT_RE.test(c));
  ACTIVE = null;
  for (const c of candidates) {
    if (await roleIn(c, me)) {
      ACTIVE = c;
      rememberDeploy(me, c);
      store.set(activeKey(me), c);
      return;
    }
  }
}

async function syncWallet() {
  if (DEMO) wallet = demo.wallet;
  else if (selector?.isSignedIn()) wallet = await selector.wallet().catch(() => null);
  else wallet = null;
  const me = connectedAccount();
  const changed = me !== lastAccount;
  lastAccount = me;
  if (changed) {
    renderWho();
    if (!DEMO) { ACTIVE = null; makeView(); renderEmpty(); } // never show the previous account's data while resolving
    await resolveActive();
    makeView();
    currentIntent = null;
  }
  renderWho();
  applyRoles();
  if (changed) load().catch(console.error);
}

async function initWallet() {
  if (DEMO) {
    $("connect").addEventListener("click", () => toast("Demo mode", { detail: "Remove ?demo from the URL to use a real wallet." }));
    return syncWallet();
  }
  selector = await setupWalletSelector({
    network: "testnet",
    // Meteor hands apps a function-call key, so DeployContract is rejected;
    // MyNearWallet and Nightly sign with a full-access key, so in-app deploy works.
    modules: [setupMyNearWallet({ walletUrl: "https://testnet.mynearwallet.com" }), setupNightly(), setupMeteorWallet()],
  });
  modal = setupModal(selector, { contractId: ACTIVE || undefined });
  $("connect").addEventListener("click", async () => {
    if (selector.isSignedIn()) {
      $("connect").disabled = true;
      try { await (await selector.wallet()).signOut(); } catch (e) { console.error("sign-out failed", e); }
      finally { $("connect").disabled = false; await syncWallet(); }
      return;
    }
    modal.show();
  });
  selector.on("signedIn", () => syncWallet());
  selector.on("signedOut", () => syncWallet());
  selector.on("accountsChanged", () => syncWallet());
  window.addEventListener("focus", () => syncWallet());
  document.addEventListener("visibilitychange", () => { if (!document.hidden) syncWallet(); });
  await syncWallet();
}

async function callContract(method, args, deposit = "0", contractId = ACTIVE, gas = 50_000_000_000_000n) {
  if (!wallet) throw new Error("Connect a NEAR wallet first (top-right button).");
  if (!contractId) throw new Error("No active contract — deploy one in Setup or switch to an existing one.");
  const signerId = connectedAccount();
  if (!signerId) throw new Error("Wallet reports no signed-in account — reconnect.");
  return wallet.signAndSendTransaction({
    signerId,
    receiverId: contractId,
    actions: [nearAction(method, args, gas, BigInt(deposit))],
  });
}

// Runs a wallet action, reports with a toast + the action log, then refreshes.
async function act(btn, label, fn) {
  const out = $("action-out");
  return busy(btn, `${label}…`, async () => {
    out.innerHTML = `<span class="hint">Waiting for wallet signature…</span>`;
    try {
      const res = await fn();
      const hash = txHash(res);
      out.innerHTML = `${pill(`${label} sent`, "ok")} ${hash ? `<a class="mono" href="https://testnet.nearblocks.io/txns/${encodeURIComponent(hash)}" target="_blank" rel="noreferrer">${esc(hash)}</a>` : `<span class="hint">The wallet returned no hash (it may redirect to its own page) — check the explorer, then Refresh.</span>`}`;
      toast(`${label} sent`, { tx: hash, kind: "ok" });
      await load();
    } catch (err) {
      out.innerHTML = `${pill(`${label} failed`, "bad")} <span class="mono">${esc(errMsg(err))}</span>`;
      toast(`${label} failed`, { detail: errMsg(err), kind: "bad" });
    }
  });
}

// ───────────────── health / shield ─────────────────
// v3 stores one daily limit per chain (in that chain's smallest unit).
const ethLimit = (p) => p?.daily_limits?.eth ?? p?.daily_limits?.ETH ?? Object.values(p?.daily_limits || {})[0] ?? null;

function computeHealth() {
  const checks = [];
  const add = (level, title, detail) => checks.push({ level, title, detail });
  const p = S.policy;
  if (!p) {
    add("bad", "Contract not readable", `${ACTIVE} did not answer get_policy — is it deployed and initialised?`);
    return checks;
  }
  if (S.panicked) add("bad", "Panic mode is ON", "All spending is frozen. The owner can unfreeze after the cooldown.");
  else add("ok", "Panic mode is off", "Spending is allowed under the policy.");

  if (S.reviewer) add("ok", "AI reviewer appointed", `Verdicts come from ${S.reviewer}.`);
  else add("warn", "No AI reviewer set", "The AI gate is off — transfers are decided by plain rules only.");

  const g = S.guardians.length;
  if (g === 0) add("bad", "No guardians", "Nobody can trigger panic or escalate holds.");
  else if (g < Number(p.guard_threshold)) add("warn", "Not enough guardians", `${g} guardian(s) but the threshold is ${p.guard_threshold}: holds can never be cleared.`);
  else add("ok", "Guardians in place", `${g} guardian(s), threshold ${p.guard_threshold}.`);

  let limit = NaN;
  const lim = ethLimit(p);
  try { limit = Number(formatEther(BigInt(lim))); } catch { /* ignore */ }
  if (limit > 1000) add("bad", "Daily limit is effectively unlimited", `${fmtEth(lim)} ETH per day — set a realistic cap (propose_daily_limit).`);
  else if (limit > 10) add("warn", "Daily limit is high", `${fmtEth(lim)} ETH per day.`);
  else if (Number.isFinite(limit)) add("ok", "Daily limit is sensible", `${fmtEth(lim)} ETH per day.`);
  else add("warn", "No daily limit configured", "Unlisted chains share the `other` bucket and are denied until a limit is set.");

  const quiet = Number(p.quiet_period);
  if (quiet < 3600e9) add("warn", "Quiet period is very short", `${fmtNs(quiet)} — the contract stores nanoseconds; a value in seconds would show up like this.`);
  const cool = Number(p.panic_cooldown);
  if (cool < 3600e9) add("warn", "Panic cooldown is very short", `${fmtNs(cool)} — fine for tests, risky in production.`);
  return checks;
}

function renderShield(checks) {
  const worst = checks.some((c) => c.level === "bad") ? "bad" : checks.some((c) => c.level === "warn") ? "warn" : "ok";
  const frozen = S.panicked;
  const copy = {
    ok: ["Protected", "Every guardrail checked below is in place."],
    warn: ["Needs attention", "Working, but some guardrails are missing or loose."],
    bad: [frozen ? "Frozen" : "At risk", frozen ? "Panic mode is on — all spending is blocked." : "A critical guardrail is missing. Fix it before using real funds."],
  }[worst];
  const shield = $("shield");
  shield.dataset.state = worst;
  $("shield-title").textContent = copy[0];
  $("shield-sub").textContent = copy[1];
  const order = { bad: 0, warn: 1, ok: 2 };
  const sorted = [...checks].sort((a, b) => order[a.level] - order[b.level]);
  $("health").innerHTML = sorted
    .map((c) => `<li class="h-${c.level}"><span class="h-ico" aria-hidden="true"></span><div><b>${esc(c.title)}</b><span>${esc(c.detail)}</span></div></li>`)
    .join("");
}

// ───────────────── dashboard render ─────────────────
function renderEmpty() {
  const me = connectedAccount();
  const msg = me
    ? `No Aegis contract selected for ${esc(me)}. Deploy one in Setup below, or switch to an existing contract.`
    : "Connect a NEAR wallet to see your Aegis contract.";
  const p = `<p class="empty">${msg}</p>`;
  Object.assign(S, { operator: null, guardians: [], policy: null, reviewer: null, panicked: false, ethAddress: null });
  const shield = $("shield");
  shield.dataset.state = "idle";
  $("shield-title").textContent = me ? "No contract yet" : "Not connected";
  $("shield-sub").textContent = me ? "Deploy your own Aegis contract to see its guardrails." : "Connect a wallet to inspect or deploy your own policy.";
  $("health").innerHTML = "";
  $("stats").innerHTML = [statTile("Panic mode", "—"), statTile("Daily limit", "—"), statTile("Guardians", "—"), statTile("Sepolia balance", "—")].join("");
  if (me) {
    const myList = getMyDeploys(me);
    const accountRows = [row("connected wallet", acct(me))];
    if (myList.length) accountRows.push(row("your contracts", myList.map((c) => `<a href="#" data-switch-contract="${esc(c)}">${esc(c)}</a>`).join("<br>")));
    accountRows.push(row("active contract", `<span class="muted">${esc(msg)}</span>`));
    $("accounts").innerHTML = accountRows.join("");
  } else {
    $("accounts").innerHTML = `<tr><td>${p}</td></tr>`;
  }
  for (const id of ["policy", "verdicts", "inheritance", "payroll", "chainsig"]) $(id).innerHTML = `<tr><td>${p}</td></tr>`;
  for (const id of ["holds", "pending"]) $(id).innerHTML = p;
  $("verdict-out").innerHTML = "";
  $("transfer-out").innerHTML = "";
}

async function load() {
  $("active-contract").textContent = ACTIVE || "—";
  if (!viewC) return renderEmpty();
  const me0 = connectedAccount();
  const [operator, policy, reviewer, guardians, panicked] = await Promise.all([
    safe(() => viewC.get_operator()),
    safe(() => viewC.get_policy()),
    safe(() => viewC.get_reviewer()),
    safe(() => viewC.get_guardians(), []),
    safe(() => viewC.is_panicked(), false),
  ]);
  Object.assign(S, { operator, policy, reviewer, guardians: guardians || [], panicked: !!panicked });
  renderWho();
  applyRoles();

  // Derived address belongs to the connected wallet (path ethereum-1) — never to someone else's operator.
  const ethAddress = me0 ? await deriveEthAddress(me0) : null;
  S.ethAddress = ethAddress;
  const balance = ethAddress ? await safe(() => eth.getBalance({ address: ethAddress })) : null;

  renderShield(computeHealth());

  $("stats").innerHTML = [
    statTile("Panic mode", panicked ? pill("frozen", "bad") : pill("off", "ok")),
    statTile("Daily limit", policy ? `${fmtEth(ethLimit(policy))} <small>ETH</small>` : "—", "eth, per day"),
    statTile("Guardians", policy ? `${S.guardians.length} <small>of ${esc(policy.guard_threshold)} needed</small>` : "—"),
    statTile("Sepolia balance", balance != null ? `${Number(formatEther(balance)).toFixed(4)} <small>ETH</small>` : "—", ethAddress ? "your wallet's derived address" : "connect a wallet"),
  ].join("");

  const me = connectedAccount();
  const myList = getMyDeploys(me);
  const canManage = !!me && (isOperator() || isGuardian() || myList.includes(ACTIVE));
  const accountRows = [row("connected wallet", me ? acct(me) : `<span class="muted">not connected</span>`)];
  if (me && myList.length) {
    accountRows.push(row("your contracts", myList.map((c) => `<a href="#" data-switch-contract="${esc(c)}">${esc(c)}</a>${c === ACTIVE ? ` ${pill("active", "ok")}` : ""}`).join("<br>")));
  }
  accountRows.push(row("active contract", acct(ACTIVE)));
  if (!me) {
    accountRows.length = 0;
    accountRows.push(`<tr><td><p class="empty">Connect a NEAR wallet to see your accounts.</p></td></tr>`);
  } else if (canManage) {
    accountRows.push(row("operator", operator ? acct(operator) : "—"));
    accountRows.push(row("AI reviewer", reviewer ? acct(reviewer) : `<span class="muted">not set</span>`));
    accountRows.push(row("guardians", S.guardians.length ? S.guardians.map(acct).join("<br>") : `<span class="muted">none</span>`));
  } else {
    accountRows.push(row("contract accounts", `<span class="muted">Connect the operator/guardian wallet or deploy your own contract to view and manage its accounts.</span>`));
  }
  if (me) accountRows.push(row("MPC network", acct(MPC)));
  $("accounts").innerHTML = accountRows.join("");

  $("policy").innerHTML = policy
    ? [
        ...Object.entries(policy.daily_limits || {}).map(([c, v]) => row(`daily limit · ${c}`, c.toLowerCase() === "eth" ? `${fmtEth(v)} ETH <span class="muted">per day</span>` : `${esc(v)} <span class="muted">smallest unit / day</span>`)),
        row("AI verdict TTL", fmtNs(policy.verdict_ttl)),
        row("quiet period", `${fmtNs(policy.quiet_period)} <span class="muted">first-seen addresses are held</span>`),
        row("guardian threshold", esc(policy.guard_threshold ?? "—")),
        row("known-address grace", fmtNs(policy.known_grace)),
        row("panic cooldown", fmtNs(policy.panic_cooldown)),
      ].join("")
    : row("—", "contract not initialised — see Setup below");

  $("verdicts").innerHTML = [
    row("deny rule", `risk ≥ 70 <span class="muted">or an explicit deny from the reviewer</span>`),
    row("no verdict", S.reviewer ? pill("denied", "bad") + ` <span class="hint">a reviewer is set, so every transfer needs a fresh verdict</span>` : pill("rules only", "warn")),
    row("validity", `${fmtNs(policy?.verdict_ttl)} <span class="muted">single-use, bound to the exact transfer + nonce</span>`),
  ].join("");

  await renderHolds();
  await renderPending();

  const [lastCheckin, heirs, inheritanceOpen, employees, payrollRuns] = await Promise.all([
    safe(() => viewC.get_last_checkin()),
    safe(() => viewC.get_heirs(), []),
    safe(() => viewC.is_inheritance_open()),
    safe(() => viewC.get_employees(), []),
    safe(() => viewC.get_payroll_runs()),
  ]);
  $("inheritance").innerHTML = [
    row("last check-in", fmtDate(lastCheckin)),
    row("heirs", (heirs || []).length ? heirs.map(esc).join("<br>") : `<span class="muted">none</span>`),
    row("state", inheritanceOpen ? pill("open — heirs whitelisted", "warn") : pill("closed (owner active)", "ok")),
  ].join("");
  $("payroll").innerHTML = [
    row("employees", (employees || []).length ? employees.map((e) => `${esc(e.address)} — ${fmtEth(e.salary)} ETH/run`).join("<br>") : `<span class="muted">none</span>`),
    row("payroll runs", esc(payrollRuns ?? "—")),
  ].join("");

  $("chainsig").innerHTML = [
    row("NEAR account", me0 ? acct(me0) : `<span class="muted">not connected</span>`),
    row("derived ETH address", ethAddress ? `<code>${esc(ethAddress)}</code>` : me0 ? `<span class="muted">could not derive</span>` : `<span class="muted">connect a wallet</span>`),
    row("Sepolia balance", balance != null ? `${esc(formatEther(balance))} ETH` : "—"),
    row("derivation path", `<code>${ETH_PATH}</code>`),
  ].join("");
}

function verdictCell(v) {
  const risky = v.denied || v.risk >= 70;
  return `${pill(risky ? "DENY" : "pass", risky ? "bad" : "ok")} <span class="hint">risk ${esc(v.risk)}/100 · ${esc(v.model)}</span>`;
}

function statusLabel(st) {
  if (typeof st === "string") return st;
  if (st && typeof st === "object") {
    const [k, v] = Object.entries(st)[0] ?? [];
    return k === "Cleared" && v?.release_at ? `Cleared — releases ${fmtDate(v.release_at)}` : String(k ?? "—");
  }
  return "—";
}
async function renderHolds() {
  const box = $("holds");
  const rows = [];
  let misses = 0;
  for (let id = 1; id <= HOLD_SCAN_LIMIT && misses < 2; id++) {
    const h = await safe(() => viewC.get_hold({ id }));
    if (!h) { misses++; continue; }
    misses = 0;
    const capsule = Number(h.capsule_release_at) > 0;
    const st = statusLabel(h.status);
    const kind = /Cancelled/.test(st) ? "bad" : /Released/.test(st) ? "ok" : /Cleared/.test(st) ? "info" : "neutral";
    rows.push(`<tr>
      <td class="mono">#${id}</td>
      <td>${capsule ? pill("capsule", "info") : pill("hold")}</td>
      <td class="mono wrap">${esc(h.chain)} → ${esc(h.to)}</td>
      <td class="mono">${fmtEth(h.amount)} ETH</td>
      <td>${pill(st, kind)}</td>
      <td class="muted">${capsule ? `opens ${esc(fmtDate(h.capsule_release_at))}${h.message ? ` · “${esc(h.message)}”` : ""}` : `${(h.escrow || []).length} guardian vote(s)`}</td>
    </tr>`);
  }
  box.innerHTML = rows.length
    ? `<div class="table-wrap"><table class="grid-table"><thead><tr><th>id</th><th>type</th><th>transfer</th><th>amount</th><th>status</th><th>details</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`
    : `<p class="empty">No holds or capsules on this contract yet.</p>`;
}

// ───────────────── pending admin changes (timelock + veto) ─────────────────
function applyCallFor(action) {
  const fixed = {
    reviewer: ["apply_reviewer", {}],
    reviewer_none: ["apply_reviewer_none", {}],
    panic_cooldown: ["apply_panic_cooldown", {}],
    quiet_period_ns: ["apply_quiet_period_ns", {}],
    set_inheritance_timeout: ["apply_set_inheritance_timeout", {}],
    ai_deny_threshold: ["apply_ai_deny_threshold", {}],
    guard_threshold: ["apply_guard_threshold", {}],
    admin_delay: ["apply_admin_delay", {}],
    known_grace: ["apply_known_grace", {}],
    verdict_ttl: ["apply_verdict_ttl", {}],
    set_heirs: ["apply_set_heirs", {}],
  };
  if (fixed[action]) return fixed[action];
  if (action.startsWith("whitelist_add:")) {
    const rest = action.slice("whitelist_add:".length);
    const i = rest.indexOf(":");
    if (i > 0) return ["apply_whitelist_add", { chain: rest.slice(0, i), address: rest.slice(i + 1) }];
  }
  if (action.startsWith("guardian_add:")) return ["apply_guardian_add", { account: action.slice("guardian_add:".length) }];
  if (action.startsWith("guardian_remove:")) return ["apply_guardian_remove", { account: action.slice("guardian_remove:".length) }];
  if (action.startsWith("daily_limit:")) return ["apply_daily_limit", { chain: action.slice("daily_limit:".length) }];
  if (action.startsWith("add_employee:")) return ["apply_add_employee", { address: action.slice("add_employee:".length) }];
  return [null, {}];
}

function prettyPayload(payload) {
  try { return JSON.stringify(JSON.parse(payload)); } catch { return String(payload ?? ""); }
}

async function renderPending() {
  const box = $("pending");
  if (!box) return;
  const [proposals, delay] = await Promise.all([
    safe(() => viewC.get_admin_proposals(), []),
    safe(() => viewC.get_admin_delay(), 0),
  ]);
  const list = proposals || [];
  if (!list.length) {
    box.innerHTML = `<p class="empty">No pending admin changes.</p>`;
    return;
  }
  const now = Date.now() * 1e6;
  const rows = list.map(([action, payload, proposedAt]) => {
    const [method, args] = applyCallFor(action);
    const eligibleAt = Number(proposedAt) + Number(delay);
    const ready = now >= eligibleAt;
    return `<tr>
      <td class="mono wrap">${esc(action)}</td>
      <td class="mono wrap">${esc(prettyPayload(payload))}</td>
      <td>${ready ? pill("ready", "ok") : pill(`after ${fmtDate(eligibleAt)}`, "warn")}</td>
      <td class="actions">${method ? `<button class="btn btn-sm" data-apply="${esc(action)}" data-method="${esc(method)}" data-args="${esc(JSON.stringify(args))}" ${ready ? "" : "disabled"}>Apply</button>` : ""}
        <button class="btn btn-ghost btn-sm" data-veto="${esc(action)}" data-role="guardian">Veto</button></td>
    </tr>`;
  }).join("");
  box.innerHTML = `<div class="table-wrap"><table class="grid-table"><thead><tr><th>action</th><th>payload — what will be applied</th><th>timelock</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  box.querySelectorAll("button[data-apply]").forEach((btn) => btn.addEventListener("click", () => {
    act(btn, "apply change", () => callContract(btn.dataset.method, JSON.parse(btn.dataset.args || "{}")));
  }));
  box.querySelectorAll("button[data-veto]").forEach((btn) => btn.addEventListener("click", () => {
    if (!confirm(`Veto "${btn.dataset.veto}"?`)) return;
    act(btn, "veto", () => callContract("guardian_veto", { action: btn.dataset.veto }));
  }));
}

// ───────────────── verdict lookup ─────────────────
$("verdict-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const hash = new FormData(e.target).get("hash").trim();
  const out = $("verdict-out");
  if (!hash) return;
  if (!viewC) return toast("No active contract", { detail: "Connect a wallet and deploy or switch to a contract first.", kind: "bad" });
  const v = await safe(() => viewC.get_ai_verdict({ intent_hash: hash }));
  out.innerHTML = v
    ? `${verdictCell(v)} <span class="hint">reviewed ${esc(fmtDate(v.reviewed_at))}</span>`
    : `${pill("no verdict", "warn")} <span class="hint">nothing on-chain for <span class="mono">${esc(hash)}</span> — with a reviewer set, a transfer without a verdict is denied.</span>`;
});

// ───────────────── transfer wizard ─────────────────
function markStep(n) {
  document.querySelectorAll(".step").forEach((el, i) => {
    el.classList.toggle("done", i + 1 < n);
    el.classList.toggle("active", i + 1 === n);
  });
}
markStep(1);

$("transfer-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const chain = fd.get("chain").trim();
  const to = fd.get("to").trim();
  const amount = fd.get("amount").trim();
  const memo = fd.get("memo").trim();
  if (!viewC) return toast("No active contract", { detail: "Connect a wallet and deploy or switch to a contract first.", kind: "bad" });
  if (!/^\d+$/.test(amount)) return toast("Amount must be a whole number of wei", { kind: "bad" });
  const memoHash = await sha256hex(memo);
  const nonce = Number((await safe(() => viewC.get_nonce())) ?? 0);
  const args = { chain, to, amount, memo_hash: memoHash, nonce };
  // The contract computes the verdict key itself — never re-implement it client-side.
  const ih = (await safe(() => viewC.compute_intent_hash(args))) || (await sha256hex(`${chain.toLowerCase()}|${to.toLowerCase()}|${amount}|${memoHash}|${nonce}`));
  currentIntent = { ...args, memo, ih };
  const verdict = await safe(() => viewC.get_ai_verdict({ intent_hash: ih }));
  const sim = await safe(() => viewC.simulate_tx(args));
  const tone = sim === "Approve" ? "ok" : sim === "Hold" ? "warn" : sim === "Deny" ? "bad" : "neutral";
  $("transfer-out").innerHTML = `
    <div class="result-row"><span class="muted">nonce</span><code>${nonce}</code></div>
    <div class="result-row"><span class="muted">intent hash</span><code class="wrap">${esc(ih)}</code></div>
    <div class="result-row"><span class="muted">verdict on-chain</span>${verdict ? verdictCell(verdict) : `${pill("none", "warn")} <span class="hint">run step 2</span>`}</div>
    <div class="result-row"><span class="muted">contract says</span>${pill(sim ?? "unknown", tone)}</div>`;
  const review = JSON.stringify({ chain, to, amount, token: "ETH", memo });
  $("cmd-review").innerHTML = `<code>node tools/reviewer/review.mjs --submit '${esc(review)}'</code>`;
  $("copy-review").disabled = false;
  $("copy-review").dataset.copy = `node tools/reviewer/review.mjs --submit '${review}'`;
  $("do-sign").disabled = false;
  $("do-sign").dataset.copy = `node tools/chainsig/sign-eth.mjs ${to} ${formatEther(BigInt(amount))}`;
  const wl = $("whitelist-address");
  if (wl && !wl.value.trim()) wl.value = to;
  markStep(verdict ? 3 : 2);
  applyRoles();
});

async function copyFrom(btn, label) {
  try {
    await navigator.clipboard.writeText(btn.dataset.copy || "");
    toast(label, { kind: "ok" });
  } catch {
    toast("Clipboard blocked", { detail: "Select the command above and copy it manually.", kind: "bad" });
  }
}
$("copy-review").addEventListener("click", (e) => copyFrom(e.currentTarget, "Reviewer command copied"));
$("do-sign").addEventListener("click", (e) => copyFrom(e.currentTarget, "Sign command copied — run it next to your operator key"));

$("do-evaluate").addEventListener("click", (e) => {
  if (!currentIntent) return toast("Compute the intent hash first", { kind: "bad" });
  act(e.currentTarget, "evaluate_tx", () =>
    callContract("evaluate_tx", { chain: currentIntent.chain, to: currentIntent.to, amount: currentIntent.amount, memo_hash: currentIntent.memo_hash, nonce: currentIntent.nonce })
  ).then(() => markStep(3));
});

// ───────────────── owner & guardian actions ─────────────────
const holdId = (value) => {
  const n = Number(String(value).trim());
  return Number.isInteger(n) && n > 0 ? n : null;
};

$("whitelist-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const to = (new FormData(e.target).get("address").trim() || currentIntent?.to || "");
  if (!/^0x[0-9a-fA-F]{40}$/.test(to)) return toast("Not a valid EVM address", { detail: to || "Enter the 0x… address first.", kind: "bad" });
  act($("act-whitelist"), "propose whitelist", () => callContract("propose_whitelist_add", { chain: "eth", address: to }));
});
$("cancel-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const id = holdId(new FormData(e.target).get("id"));
  if (!id) return toast("Enter a hold id (a positive number)", { kind: "bad" });
  act($("act-cancel"), "cancel hold", () => callContract("cancel_hold", { id }, "0"));
});
$("release-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const id = holdId(new FormData(e.target).get("id"));
  if (!id) return toast("Enter a hold id (a positive number)", { kind: "bad" });
  act($("act-release"), "release hold", () => callContract("release_hold", { id }));
});
$("escalate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const id = holdId(new FormData(e.target).get("id"));
  if (!id) return toast("Enter a hold id (a positive number)", { kind: "bad" });
  act($("act-escalate"), "escalate", () => callContract("hold_escalate", { id }));
});
$("act-checkin").addEventListener("click", (e) => act(e.currentTarget, "check-in", () => callContract("check_in", {})));
$("act-payroll").addEventListener("click", (e) => act(e.currentTarget, "payroll", () => callContract("run_payroll", { chain: "eth" })));
$("act-panicoff").addEventListener("click", (e) => act(e.currentTarget, "panic off", () => callContract("panic_off", {})));
$("act-panicon").addEventListener("click", (e) => {
  if (!confirm("Freeze ALL spending on this contract? Only the owner can unfreeze it, after the cooldown.")) return;
  act(e.currentTarget, "panic", () => callContract("panic_on", {}));
});

// ───────────────── setup: deploy / configure / switch ─────────────────
const WALLET_DEPLOY_BLOCK = /deploycontract|deploy contract|contract code|control of your account/i;

function deployBlockedHelp({ account, operator, threshold, fund }) {
  const acctId = account || "aegis.yourname.testnet";
  const op = operator || "yourname.testnet";
  const thr = Number(threshold) || 1;
  const create = `near account create-account fund-myself ${acctId} '${fund || 5} NEAR' autogenerate-new-keypair save-to-keychain sign-as ${op} network-config testnet sign-with-keychain send`;
  const deploy = `near contract deploy ${acctId} use-file frontend/public/watchdog.wasm with-init-call new json-args '{"operator":"${op}","guard_threshold":${thr}}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send`;
  return `<div class="note warn"><b>${esc(op)}'s wallet can't deploy contracts from a dApp.</b>
    Meteor and Sender only grant function-call keys. Either connect with <b>MyNearWallet</b> or <b>Nightly</b>, or deploy once from a terminal and then use “Switch”.</div>
    <pre class="cmd"><code>${esc(create)}</code></pre><pre class="cmd"><code>${esc(deploy)}</code></pre>
    <button class="btn btn-ghost btn-sm" type="button" data-copy="${esc(`${create}\n${deploy}`)}">Copy commands</button>
    <p class="hint">Check the exact sub-commands with <code>near account create-account --help</code> — they differ between near-cli-rs versions.</p>`;
}
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-copy]");
  if (!btn || btn.id === "copy-review" || btn.id === "do-sign") return;
  try { await navigator.clipboard.writeText(btn.dataset.copy); btn.textContent = "Copied"; setTimeout(() => (btn.textContent = "Copy commands"), 1600); } catch { /* manual copy */ }
});

async function wasmBytes() {
  const res = await fetch("/watchdog.wasm");
  if (!res.ok) throw new Error(`watchdog.wasm not found (${res.status})`);
  return new Uint8Array(await res.arrayBuffer());
}
const minFundYocto = (bytes) => BigInt(bytes) * STORAGE_BYTE_COST + 5n * 10n ** 23n; // code storage + 0.5 NEAR for state/gas buffer

async function showDeployNeed() {
  const el = $("deploy-need");
  try {
    const wasm = await wasmBytes();
    const need = utils.format.formatNearAmount(minFundYocto(wasm.length).toString(), 2);
    el.textContent = `The contract is ${(wasm.length / 1024).toFixed(0)} KB. Storing it costs ${need} NEAR in storage staking — fund at least that, or the deploy fails with “LackBalanceForState”.`;
  } catch { el.textContent = ""; }
}

async function deployAegis({ contractAccount, fundNear, threshold, reviewer, guardian }) {
  if (!wallet) throw new Error("Connect a NEAR wallet first.");
  if (!ACCOUNT_RE.test(contractAccount)) throw new Error("That is not a valid NEAR account id.");
  const operator = connectedAccount();
  if (!contractAccount.endsWith(`.${operator}`)) throw new Error(`A new contract account must be a sub-account of ${operator} (e.g. aegis.${operator}).`);
  const th = Number(threshold) || 1;
  if (guardian && th > 1) throw new Error("Deploy initializes at most one guardian — set the threshold to 1, then add more via Pending admin changes.");
  if (reviewer && !guardian) throw new Error("A reviewer needs at least one guardian at init (threshold ≥ 1) — add the guardian field.");
  const out = $("deploy-out");
  out.innerHTML = `<span class="hint">Fetching watchdog.wasm…</span>`;
  const wasm = await wasmBytes();
  const deposit = BigInt(utils.format.parseNearAmount(String(fundNear)) ?? "0");
  if (deposit < minFundYocto(wasm.length)) {
    throw new Error(`Not enough funding: ${fundNear} NEAR is below the ${utils.format.formatNearAmount(minFundYocto(wasm.length).toString(), 2)} NEAR the code needs.`);
  }
  // V1: configure everything atomically at init; no instant post-init setters.
  const method = guardian ? "new_configured" : "new";
  const args = guardian
    ? { operator, guard_threshold: th, admin_delay: ADMIN_DAY_NS, reviewer: reviewer || null, guardians: [guardian], whitelist: [] }
    : { operator, guard_threshold: th };
  out.innerHTML = `<span class="hint">One wallet transaction: create account + fund + deploy + init — confirm in your wallet.</span>`;
  const res = await wallet.signAndSendTransaction({
    signerId: operator,
    receiverId: contractAccount,
    actions: [
      actionCreators.createAccount(),
      actionCreators.transfer(deposit),
      actionCreators.deployContract(wasm),
      actionCreators.functionCall(method, Buffer.from(JSON.stringify(args)), 50_000_000_000_000n, 0n),
    ],
  });
  rememberDeploy(operator, contractAccount);
  out.innerHTML = `${pill("deployed", "ok")} <span class="mono">${esc(txHash(res) || "sent — check the explorer")}</span> <span class="hint">Switching the dashboard to the new contract…</span>`;
  switchActive(contractAccount);
}

$("deploy-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const account = fd.get("account").trim().toLowerCase();
  const threshold = fd.get("threshold").trim() || "1";
  const fund = fd.get("fund").trim() || "5";
  const reviewer = fd.get("reviewer").trim();
  const guardian = fd.get("guardian").trim();
  if (!(Number(threshold) >= 1)) return toast("Threshold must be at least 1", { kind: "bad" });
  for (const a of [reviewer, guardian]) if (a && !ACCOUNT_RE.test(a)) return toast("Invalid NEAR account id", { detail: a, kind: "bad" });
  await busy(e.target.querySelector("button[type=submit]"), "Deploying…", async () => {
    try {
      await deployAegis({ contractAccount: account, fundNear: fund, threshold, reviewer, guardian });
    } catch (err) {
      const msg = errMsg(err);
      $("deploy-out").innerHTML = WALLET_DEPLOY_BLOCK.test(msg)
        ? deployBlockedHelp({ account, operator: connectedAccount(), threshold, fund })
        : `${pill("deploy failed", "bad")} <span class="mono">${esc(msg)}</span>`;
    }
  });
});

$("configure-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const reviewer = fd.get("reviewer").trim();
  const guardian = fd.get("guardian").trim();
  const out = $("deploy-out");
  if (!wallet) return toast("Connect a wallet first", { kind: "bad" });
  for (const a of [reviewer, guardian]) if (a && !ACCOUNT_RE.test(a)) return toast("Invalid NEAR account id", { detail: a, kind: "bad" });
  const steps = [];
  if (reviewer) steps.push({ methodName: "propose_reviewer", args: { reviewer } });
  if (guardian) steps.push({ methodName: "propose_guardian_add", args: { account: guardian } });
  if (!steps.length) return toast("Enter a reviewer and/or a guardian", { kind: "bad" });
  await busy(e.target.querySelector("button[type=submit]"), "Sending…", async () => {
    try {
      for (const s of steps) {
        out.innerHTML = `<span class="hint">Calling ${esc(s.methodName)}… confirm in your wallet.</span>`;
        const res = await callContract(s.methodName, s.args);
        out.innerHTML = `${pill(`${s.methodName} sent`, "ok")} <span class="mono">${esc(txHash(res) || "sent")}</span>`;
      }
      out.innerHTML += `<p class="hint">Apply these from “Pending admin changes” after the timelock (guardians can veto meanwhile).</p>`;
      await load();
    } catch (err) {
      out.innerHTML = `${pill("configure failed", "bad")} <span class="mono">${esc(errMsg(err))}</span>`;
    }
  });
});

function switchActive(id) {
  ACTIVE = id;
  const me = connectedAccount();
  if (me) store.set(activeKey(me), id);
  makeView();
  currentIntent = null;
  load().catch(console.error);
}
$("switch-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const id = new FormData(e.target).get("contract").trim().toLowerCase();
  if (!ACCOUNT_RE.test(id)) return toast("Invalid NEAR account id", { detail: id, kind: "bad" });
  switchActive(id);
});

$("accounts").addEventListener("click", (e) => {
  const a = e.target.closest("[data-switch-contract]");
  if (!a) return;
  e.preventDefault();
  switchActive(a.dataset.switchContract);
});

$("refresh").addEventListener("click", (e) => busy(e.currentTarget, "Refreshing…", () => load().catch(console.error)));

// ───────────────── boot ─────────────────
$("active-contract").textContent = ACTIVE || "—";
showDeployNeed();
await initView().catch((e) => { console.error(e); toast("Could not reach NEAR RPC", { detail: errMsg(e), kind: "bad" }); });
await initWallet().catch((e) => { console.error(e); $("who").textContent = "Wallet unavailable"; });
if (!lastAccount) await load().catch(console.error); // syncWallet already loads when a wallet is restored

// Dev-only handle for poking at wallet state in the console.
if (import.meta.env.DEV) {
  window.__aegis = { get selector() { return selector; }, syncWallet, renderWho, deployBlockedHelp, S };
}
