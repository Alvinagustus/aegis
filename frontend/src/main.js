// Aegis dashboard — C1 guided demo (instant simulated + read-only live on-chain).
// No wallet connection in the main UI. Read-only by design.
import { Buffer } from "buffer";
import { connect, Contract, keyStores } from "near-api-js";
import { createPublicClient, http, formatEther } from "viem";
import { sepolia } from "viem/chains";

// Some NEAR dependency bundles expect the Node Buffer global.
if (!globalThis.Buffer) globalThis.Buffer = Buffer;

// ───────────────── constants ─────────────────
const params = new URLSearchParams(location.search);
const MODE = params.has("demo") ? "sim" : (params.get("mode") === "live" || params.has("live") ? "live" : null);
const LIVE_CONTRACT = "aegispolicy.testnet";
const MPC = "v1.signer-prod.testnet";
const ETH_PATH = "ethereum-1";
const SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com";
const NODE_URL = "https://test.rpc.fastnear.com";
const HOLD_SCAN_LIMIT = 15;

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
const safe = async (fn, fallback = null) => { try { return await fn(); } catch { return fallback; } };
async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fmtEth(wei) {
  if (wei == null) return "—";
  let n;
  try { n = Number(formatEther(BigInt(wei))); } catch { return "—"; }
  if (n === 0) return "0";
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: n >= 1 ? 2 : 6 }).format(n);
}
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

// ───────────────── state ─────────────────
let ACTIVE = null;
let viewC = null;
let demo = null;
let eth = null;
let currentIntent = null;
let mode = MODE; // "sim" | "live" | null
const S = { operator: null, guardians: [], policy: null, reviewer: null, panicked: false, ethAddress: null };
const ethCache = new Map();
const simVerdicts = new Map(); // client-side verdict overlay for web demo flows
const simState = {
  panicked: false,
  whitelist: new Set(),
  extraHolds: [], // {id, ...} for live-demo capsules/holds created in-browser
  nextHoldId: 1000,
  employees: null, // null = use chain; array = overlay list
  payrollRunsDelta: 0,
  inheritance: null, // {lastCheckin, heirs, open, timeoutNs} overlay for live demo
};

function scoreMemo(memo = "") {
  const m = String(memo).toLowerCase();
  const risky = /(seed|phrase|private key|verify|migration|airdrop|claim now|urgent|support|wallet migration)/.test(m);
  return risky ? { risk: 100, denied: true, reason: "phishing-like request detected" } : { risk: 5, denied: false, reason: "no obvious risk signals" };
}

// ───────────────── chain access ─────────────────
const VIEW_METHODS = ["get_operator", "get_policy", "get_reviewer", "get_guardians", "is_panicked", "get_ai_verdict", "get_hold", "simulate_tx", "is_whitelisted", "get_nonce", "compute_intent_hash", "get_last_checkin", "get_heirs", "is_inheritance_open", "get_employees", "get_payroll_runs", "get_admin_proposals", "get_admin_delay"];

function makeView() {
  if (mode === "sim") return; // demo provides viewC
  viewC = ACTIVE && window.__nearAccount ? new Contract(window.__nearAccount, ACTIVE, { viewMethods: VIEW_METHODS, changeMethods: [] }) : null;
}

async function deriveEthAddress(operator) {
  if (!operator) return null;
  if (mode === "sim" && demo) return demo.ethAddress;
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

// ───────────────── mode / UI chrome ─────────────────
function isReadOnlyDemo() { return mode === "sim" || mode === "live"; }

function renderWho() {
  const who = $("who");
  if (!who) return;
  if (mode === "sim") who.innerHTML = `<span class="dot live"></span>Simulated demo`;
  else if (mode === "live") who.innerHTML = `<span class="dot live"></span>Live demo (read-only)`;
  else who.innerHTML = `<span class="dot"></span>Demo`;
  $("roles").innerHTML = "";
}

function applyRoles() {
  // Web demo: everything is simulated/interactable (no real on-chain writes from browser).
  const demoMode = isReadOnlyDemo();
  document.querySelectorAll("[data-role]").forEach((b) => {
    if (b.classList.contains("is-busy")) return;
    b.disabled = !demoMode; // enabled in demo modes as simulated actions
    b.title = demoMode ? "Simulated action (demo) — no on-chain transaction." : "";
  });
  const evalBtn = $("do-evaluate");
  if (evalBtn) {
    evalBtn.disabled = !demoMode || !currentIntent;
    $("evaluate-hint").textContent = demoMode
      ? "Web demo: verdict and evaluation run as in-browser simulations (no on-chain writes)."
      : "";
  }
  const simVerdictBtn = $("do-sim-verdict");
  if (simVerdictBtn) simVerdictBtn.disabled = !demoMode || !currentIntent;
}

function showModeUI() {
  const chooser = $("demo-chooser");
  const hero = $("top");
  const app = $("demo-app");
  const switchBtn = $("mode-switch");
  if (mode) {
    if (chooser) chooser.hidden = true;
    if (hero) hero.hidden = false;
    if (app) app.hidden = false;
    if (switchBtn) switchBtn.hidden = false;
    const eyebrow = $("mode-eyebrow");
    const lead = $("mode-lead");
    const banner = $("mode-banner");
    if (mode === "sim") {
      if (eyebrow) eyebrow.textContent = "Instant simulated demo";
      if (lead) lead.textContent = "Exploring Aegis with local, in-browser sample data. Everything here is simulated for demo — no wallet, no on-chain writes.";
      if (banner) banner.innerHTML = `${pill("Simulated demo", "warn")} <span>All interactions are simulated locally in your browser (no on-chain transactions).</span>`;
    } else {
      if (eyebrow) eyebrow.textContent = "Live on-chain demo";
      if (lead) lead.textContent = `Viewing the real ${LIVE_CONTRACT} contract state on NEAR testnet. On-chain data is read-only; demo interactions are simulated in-browser.`;
      if (banner) banner.innerHTML = `${pill("Live demo contract", "info")} <span>Reading <code>${esc(LIVE_CONTRACT)}</code> on testnet. Demo actions are simulated in-browser (no on-chain writes).</span>`;
    }
  } else {
    if (chooser) chooser.hidden = false;
    if (hero) hero.hidden = true;
    if (app) app.hidden = true;
    if (switchBtn) switchBtn.hidden = true;
  }
  renderWho();
  applyRoles();
}

async function startMode(next) {
  mode = next;
  ACTIVE = mode === "live" ? LIVE_CONTRACT : (mode === "sim" ? "aegis-demo.testnet" : null);
  currentIntent = null;
  simVerdicts.clear();
  simState.panicked = false;
  simState.whitelist.clear();
  simState.extraHolds = [];
  simState.nextHoldId = 1000;
  simState.employees = null;
  simState.payrollRunsDelta = 0;
  simState.inheritance = null;
  $("active-contract").textContent = ACTIVE || "—";
  showModeUI();
  if (!mode) return;
  try {
    if (mode === "sim") {
      const { createDemo } = await import("./demo.js");
      demo = createDemo({ healthy: params.get("demo") === "ok" });
      viewC = demo.viewC;
      eth = { getBalance: async () => demo.ethBalance };
      S.ethAddress = demo.ethAddress;
    } else {
      eth = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
      const near = await connect({ networkId: "testnet", keyStore: new keyStores.InMemoryKeyStore(), nodeUrl: NODE_URL });
      window.__nearAccount = await near.account(MPC);
      makeView();
    }
    await load();
  } catch (e) {
    console.error(e);
    toast("Could not load demo", { detail: errMsg(e), kind: "bad" });
    if ($("shield-title")) $("shield-title").textContent = "Could not load";
    if ($("shield-sub")) $("shield-sub").textContent = errMsg(e);
  }
}

// ───────────────── health / shield ─────────────────
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

function renderEmpty() {
  const msg = mode === "live"
    ? `Reading live demo contract ${LIVE_CONTRACT} on NEAR testnet…`
    : "Pick a demo to begin.";
  const p = `<p class="empty">${esc(msg)}</p>`;
  Object.assign(S, { operator: null, guardians: [], policy: null, reviewer: null, panicked: false, ethAddress: null });
  const shield = $("shield");
  shield.dataset.state = "idle";
  $("shield-title").textContent = mode === "live" ? "Loading live demo…" : "Pick a demo";
  $("shield-sub").textContent = msg;
  $("health").innerHTML = "";
  $("stats").innerHTML = [statTile("Panic mode", "—"), statTile("Daily limit", "—"), statTile("Guardians", "—"), statTile("Sepolia balance", "—")].join("");
  $("accounts").innerHTML = `<tr><td>${p}</td></tr>`;
  for (const id of ["policy", "verdicts", "inheritance", "payroll", "chainsig"]) $(id).innerHTML = `<tr><td>${p}</td></tr>`;
  for (const id of ["holds", "pending"]) $(id).innerHTML = p;
  $("verdict-out").innerHTML = "";
  $("transfer-out").innerHTML = "";
}

async function load() {
  $("active-contract").textContent = ACTIVE || "—";
  if (!viewC) return renderEmpty();

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

  // In read-only demos, show the contract operator's derived ETH address as reference (not a connected user).
  const ethAddress = mode === "sim" && demo ? demo.ethAddress : await deriveEthAddress(operator);
  S.ethAddress = ethAddress;
  const balance = ethAddress ? await safe(() => eth.getBalance({ address: ethAddress })) : null;

  renderShield(computeHealth());

  $("stats").innerHTML = [
    statTile("Panic mode", panicked ? pill("frozen", "bad") : pill("off", "ok")),
    statTile("Daily limit", policy ? `${fmtEth(ethLimit(policy))} <small>ETH</small>` : "—", "eth, per day"),
    statTile("Guardians", policy ? `${S.guardians.length} <small>of ${esc(policy.guard_threshold)} needed</small>` : "—"),
    statTile("Sepolia balance", balance != null ? `${Number(formatEther(balance)).toFixed(4)} <small>ETH</small>` : "—", ethAddress ? "contract operator's derived address" : "—"),
  ].join("");

  const demoLabel = mode === "sim" ? pill("simulated", "warn") : pill("live · read-only", "info");
  const accountRows = [
    row("mode", demoLabel),
    row("active contract", acct(ACTIVE)),
    row("operator", operator ? acct(operator) : "—"),
    row("AI reviewer", reviewer ? acct(reviewer) : `<span class="muted">not set</span>`),
    row("guardians", S.guardians.length ? S.guardians.map(acct).join("<br>") : `<span class="muted">none</span>`),
    row("MPC network", acct(MPC)),
  ];
  if (mode === "live") {
    accountRows.unshift(row("demo notice", `<span class="muted">Live on-chain demo contract (${esc(LIVE_CONTRACT)}). Read-only — not your wallet.</span>`));
  } else {
    accountRows.unshift(row("demo notice", `<span class="muted">Simulated sample data shown locally in your browser. No on-chain reads or writes.</span>`));
  }
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
    : row("—", "contract not initialised");

  $("verdicts").innerHTML = [
    row("deny rule", `risk ≥ 70 <span class="muted">or an explicit deny from the reviewer</span>`),
    row("no verdict", S.reviewer ? pill("denied", "bad") + ` <span class="hint">a reviewer is set, so every transfer needs a fresh verdict</span>` : pill("rules only", "warn")),
    row("validity", `${fmtNs(policy?.verdict_ttl)} <span class="muted">single-use, bound to the exact transfer + nonce</span>`),
  ].join("");

  await renderHolds();
  await renderPending();

  let [lastCheckin, heirs, inheritanceOpen, employees, payrollRuns] = await Promise.all([
    safe(() => viewC.get_last_checkin()),
    safe(() => viewC.get_heirs(), []),
    safe(() => viewC.is_inheritance_open()),
    safe(() => viewC.get_employees(), []),
    safe(() => viewC.get_payroll_runs()),
  ]);
  // apply web-demo overlays (live mode) so simulated actions are visible
  if (mode === "live" && simState.inheritance) {
    lastCheckin = simState.inheritance.lastCheckin ?? lastCheckin;
    heirs = simState.inheritance.heirs ?? heirs;
    inheritanceOpen = simState.inheritance.open ?? inheritanceOpen;
  }
  if (mode === "live" && simState.employees) employees = simState.employees;
  if (mode === "live" && payrollRuns != null) payrollRuns = Number(payrollRuns) + simState.payrollRunsDelta;

  $("inheritance").innerHTML = [
    row("last check-in", fmtDate(lastCheckin)),
    row("heirs", (heirs || []).length ? heirs.map(esc).join("<br>") : `<span class="muted">none</span>`),
    row("state", inheritanceOpen ? pill("open — heirs whitelisted", "warn") : pill("closed (owner active)", "ok")),
  ].join("");
  const empList = employees || [];
  $("payroll").innerHTML = [
    row("employees", empList.length ? empList.map((e) => `${esc(e.address)} — ${fmtEth(e.salary)} ETH/run`).join("<br>") : `<span class="muted">none</span>`),
    row("payroll runs", esc(payrollRuns ?? "—")),
  ].join("");

  $("chainsig").innerHTML = [
    row("reference account", operator ? acct(operator) : "—"),
    row("derived ETH address", ethAddress ? `<code>${esc(ethAddress)}</code>` : `<span class="muted">could not derive</span>`),
    row("Sepolia balance", balance != null ? `${esc(formatEther(balance))} ETH` : "—"),
    row("derivation path", `<code>${ETH_PATH}</code>`),
    row("note", `<span class="muted">Shown for reference. ${mode === "sim" ? "Simulated demo." : "Live demo contract (on-chain state read-only; actions simulated in-browser)."}</span>`),
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
  const scanLimit = mode === "sim" ? 50 : HOLD_SCAN_LIMIT;
  for (let id = 1; id <= scanLimit && (mode === "sim" ? id < (demo?.state?.nextHoldId || 50) : misses < 2); id++) {
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
  // live-demo in-browser capsules/holds overlay
  if (mode === "live" && simState.extraHolds.length) {
    for (const { id, h } of simState.extraHolds) {
      const capsule = Number(h.capsule_release_at) > 0;
      const st = statusLabel(h.status);
      const kind = /Cancelled/.test(st) ? "bad" : /Released/.test(st) ? "ok" : /Cleared/.test(st) ? "info" : "neutral";
      rows.push(`<tr>
        <td class="mono">#${id} <span class="hint">(sim)</span></td>
        <td>${capsule ? pill("capsule", "info") : pill("hold")}</td>
        <td class="mono wrap">${esc(h.chain)} → ${esc(h.to)}</td>
        <td class="mono">${fmtEth(h.amount)} ETH</td>
        <td>${pill(st, kind)}</td>
        <td class="muted">${capsule ? `opens ${esc(fmtDate(h.capsule_release_at))}${h.message ? ` · “${esc(h.message)}”` : ""}` : `${(h.escrow || []).length} guardian vote(s)`} <span class="hint">(simulated)</span></td>
      </tr>`);
    }
  }
  box.innerHTML = rows.length
    ? `<div class="table-wrap"><table class="grid-table"><thead><tr><th>id</th><th>type</th><th>transfer</th><th>amount</th><th>status</th><th>details</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`
    : `<p class="empty">No holds or capsules on this contract yet.</p>`;
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
    const eligibleAt = Number(proposedAt) + Number(delay);
    const ready = now >= eligibleAt;
    return `<tr>
      <td class="mono wrap">${esc(action)}</td>
      <td class="mono wrap">${esc(prettyPayload(payload))}</td>
      <td>${ready ? pill("ready", "ok") : pill(`after ${fmtDate(eligibleAt)}`, "warn")}</td>
      <td class="muted">Read-only demo</td>
    </tr>`;
  }).join("");
  box.innerHTML = `<div class="table-wrap"><table class="grid-table"><thead><tr><th>action</th><th>payload — what will be applied</th><th>timelock</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function verdictFor(hash) {
  if (simVerdicts.has(hash)) return simVerdicts.get(hash);
  if (mode === "sim" && demo) return demo.viewC.get_ai_verdict({ intent_hash: hash });
  return viewC?.get_ai_verdict({ intent_hash: hash });
}
async function getVerdict(hash) {
  if (simVerdicts.has(hash)) return simVerdicts.get(hash);
  const v = await safe(() => viewC.get_ai_verdict({ intent_hash: hash }));
  return v;
}

// ───────────────── verdict lookup ─────────────────
$("verdict-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const hash = new FormData(e.target).get("hash").trim();
  const out = $("verdict-out");
  if (!hash) return;
  if (!viewC) return toast("No demo loaded", { detail: "Pick a demo first.", kind: "bad" });
  const v = await getVerdict(hash);
  const local = simVerdicts.has(hash);
  out.innerHTML = v
    ? `${verdictCell(v)} <span class="hint">${local ? "simulated in browser" : "reviewed " + esc(fmtDate(v.reviewed_at))}</span>`
    : `${pill("no verdict", "warn")} <span class="hint">nothing found for <span class="mono">${esc(hash)}</span>.</span>`;
});

// ───────────────── transfer wizard (fully simulated in web demo) ─────────────────
function markStep(n) {
  document.querySelectorAll(".step").forEach((el, i) => {
    el.classList.toggle("done", i + 1 < n);
    el.classList.toggle("active", i + 1 === n);
  });
}
markStep(1);

async function simulateDecision(intent) {
  const verdict = await getVerdict(intent.ih);
  if (mode === "sim" && demo) {
    const d = await demo.viewC.simulate_tx({ ...intent, intent_hash: intent.ih });
    return { decision: d, verdict };
  }
  // live demo: client-side simulation overlay (no on-chain write)
  if (S.panicked || simState.panicked) return { decision: "Deny", verdict };
  if (!verdict) return { decision: "Deny", verdict };
  if (verdict.denied || verdict.risk >= 70) return { decision: "Deny", verdict };
  const addr = String(intent.to || "").toLowerCase();
  const wl = simState.whitelist.has(addr) || await safe(() => viewC.is_whitelisted({ chain: intent.chain, address: intent.to }), false);
  if (wl) return { decision: "Approve", verdict };
  return { decision: "Hold", verdict };
}

async function renderIntent() {
  if (!currentIntent) return;
  const verdict = await getVerdict(currentIntent.ih);
  const { decision } = await simulateDecision(currentIntent);
  const tone = decision === "Approve" ? "ok" : decision === "Hold" ? "warn" : decision === "Deny" ? "bad" : "neutral";
  $("transfer-out").innerHTML = `
    <div class="result-row"><span class="muted">nonce</span><code>${currentIntent.nonce}</code></div>
    <div class="result-row"><span class="muted">intent hash</span><code class="wrap">${esc(currentIntent.ih)}</code></div>
    <div class="result-row"><span class="muted">AI verdict</span>${verdict ? `${verdictCell(verdict)} ${simVerdicts.has(currentIntent.ih) ? `<span class="hint">(simulated)</span>` : ""}` : `${pill("none", "warn")} <span class="hint">simulate/get a verdict in step 2</span>`}</div>
    <div class="result-row"><span class="muted">decision</span>${pill(decision ?? "unknown", tone)} <span class="hint">(simulated in web demo)</span></div>`;
}

$("transfer-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const chain = fd.get("chain").trim();
  const to = fd.get("to").trim();
  const amount = fd.get("amount").trim();
  const memo = fd.get("memo").trim();
  if (!viewC) return toast("No demo loaded", { detail: "Pick a demo first.", kind: "bad" });
  if (!/^\d+$/.test(amount)) return toast("Amount must be a whole number of wei", { kind: "bad" });
  const memoHash = await sha256hex(memo);
  const nonce = Number((await safe(() => viewC.get_nonce())) ?? 0);
  const args = { chain, to, amount, memo_hash: memoHash, nonce };
  const ih = (await safe(() => viewC.compute_intent_hash(args))) || (await sha256hex(`${chain.toLowerCase()}|${to.toLowerCase()}|${amount}|${memoHash}|${nonce}`));
  currentIntent = { ...args, memo, ih, intent_hash: ih };
  const review = JSON.stringify({ chain, to, amount, token: "ETH", memo });
  $("cmd-review").innerHTML = `<code>node tools/reviewer/review.mjs --submit '${esc(review)}'</code><p class="hint">Web demo: gunakan tombol "Simulate AI verdict" di bawah (CLI opsional, untuk instance sendiri).</p>`;
  const copyReview = $("copy-review");
  copyReview.disabled = false;
  copyReview.dataset.copy = `node tools/reviewer/review.mjs --submit '${review}'`;
  const doSign = $("do-sign");
  doSign.disabled = false;
  doSign.dataset.copy = `node tools/chainsig/sign-eth.mjs ${to} ${formatEther(BigInt(amount))}`;
  await renderIntent();
  markStep(2);
  applyRoles();
});

async function doSimVerdict() {
  if (!currentIntent) return toast("Compute the intent hash first (step 1)", { kind: "bad" });
  const s = scoreMemo(currentIntent.memo);
  const v = { intent_hash: currentIntent.ih, risk: s.risk, denied: s.denied, model: "web-demo-sim", reason: s.reason, reviewed_at: String(Date.now() * 1e6) };
  if (mode === "sim" && demo) {
    demo.submitVerdict(currentIntent.ih, currentIntent.memo);
  }
  simVerdicts.set(currentIntent.ih, mode === "sim" && demo ? await demo.viewC.get_ai_verdict({ intent_hash: currentIntent.ih }) : v);
  toast("AI verdict simulated", { detail: `risk ${v.risk}/100 — ${v.denied ? "denied" : "pass"}`, kind: v.denied ? "bad" : "ok" });
  await renderIntent();
  markStep(3);
  applyRoles();
}

async function doSimEvaluate() {
  if (!currentIntent) return toast("Compute the intent hash first (step 1)", { kind: "bad" });
  await renderIntent();
  const { decision, verdict } = await simulateDecision(currentIntent);
  const tone = decision === "Approve" ? "ok" : decision === "Hold" ? "warn" : "bad";
  $("transfer-out").innerHTML += `<div class="result-row"><span class="muted">evaluate (simulated)</span>${pill(decision, tone)} <span class="hint">${decision === "Approve" ? "Would be signed & broadcast via MPC (simulated)." : decision === "Hold" ? "Held for quiet period/review (simulated)." : `Denied${!verdict ? " — no verdict" : verdict.denied || verdict.risk>=70 ? " — risky verdict" : ""} (simulated).`}</span></div>`;
  toast(`Simulated: ${decision}`, { detail: "Web demo — no on-chain transaction.", kind: tone });
  markStep(3);
}

async function copyFrom(btn, label) {
  const text = btn?.dataset?.copy || "";
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast(label, { kind: "ok" });
  } catch {
    toast("Clipboard blocked", { detail: "Select the command above and copy it manually.", kind: "bad" });
  }
}
$("copy-review").addEventListener("click", (e) => copyFrom(e.currentTarget, "Reviewer command copied"));
$("do-sign").addEventListener("click", (e) => copyFrom(e.currentTarget, "Sign command copied (for your own instance/CLI)"));
$("do-evaluate").addEventListener("click", () => doSimEvaluate());
const simVerdictBtnEl = $("do-sim-verdict");
if (simVerdictBtnEl) simVerdictBtnEl.addEventListener("click", () => doSimVerdict());

// ───────────────── simulated owner/guardian/mode actions (web demo) ─────────────────
async function refreshDemoViews() {
  if (currentIntent) await renderIntent().catch(() => {});
  await renderHolds().catch(() => {});
  // refresh inheritance/payroll panels from (possibly overlaid) state
  const employees = mode === "sim" ? await safe(() => viewC.get_employees(), []) : (simState.employees ?? await safe(() => viewC.get_employees(), []));
  let payrollRuns = await safe(() => viewC.get_payroll_runs());
  if (mode === "live" && payrollRuns != null) payrollRuns = Number(payrollRuns) + simState.payrollRunsDelta;
  const empList = employees || [];
  $("payroll").innerHTML = [
    row("employees", empList.length ? empList.map((e) => `${esc(e.address)} — ${fmtEth(e.salary)} ETH/run`).join("<br>") : `<span class="muted">none</span>`),
    row("payroll runs", esc(payrollRuns ?? "—")),
  ].join("");
  let lastCheckin = await safe(() => viewC.get_last_checkin());
  let heirs = await safe(() => viewC.get_heirs(), []);
  let inheritanceOpen = await safe(() => viewC.is_inheritance_open());
  if (mode === "live" && simState.inheritance) {
    lastCheckin = simState.inheritance.lastCheckin ?? lastCheckin;
    heirs = simState.inheritance.heirs ?? heirs;
    inheritanceOpen = simState.inheritance.open ?? inheritanceOpen;
  }
  $("inheritance").innerHTML = [
    row("last check-in", fmtDate(lastCheckin)),
    row("heirs", (heirs || []).length ? heirs.map(esc).join("<br>") : `<span class="muted">none</span>`),
    row("state", inheritanceOpen ? pill("open — heirs whitelisted", "warn") : pill("closed (owner active)", "ok")),
  ].join("");
}

$("whitelist-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const to = (new FormData(e.target).get("address").trim() || currentIntent?.to || "").toLowerCase();
  if (!to) return toast("Enter an address", { kind: "bad" });
  simState.whitelist.add(to);
  if (demo?.state?.whitelist) demo.state.whitelist.add(to);
  toast("Simulated: whitelist", { detail: `${to} ditambahkan ke whitelist (simulasi). Coba evaluate lagi untuk efeknya.`, kind: "ok" });
  if (currentIntent) renderIntent().catch(() => {});
});
$("cancel-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = Number(new FormData(e.target).get("id"));
  if (mode === "sim" && demo?.state?.holds?.[id]) demo.state.holds[id].status = "Cancelled";
  if (mode === "live") { const x = simState.extraHolds.find((h) => h.id === id); if (x) x.h.status = "Cancelled"; }
  toast("Simulated: cancel hold", { detail: `Hold #${id || "?"} (simulasi).`, kind: "ok" });
  await refreshDemoViews();
});
$("release-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = Number(new FormData(e.target).get("id"));
  if (mode === "sim" && demo?.state?.holds?.[id]) demo.state.holds[id].status = "Released";
  if (mode === "live") { const x = simState.extraHolds.find((h) => h.id === id); if (x) x.h.status = "Released"; }
  toast("Simulated: release hold", { detail: `Hold #${id || "?"} (simulasi).`, kind: "ok" });
  await refreshDemoViews();
});
$("escalate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = Number(new FormData(e.target).get("id"));
  toast("Simulated: escalate", { detail: `Guardian escalation untuk hold #${id || "?"} (simulasi).`, kind: "ok" });
  await refreshDemoViews();
});
$("act-checkin").addEventListener("click", async () => {
  if (mode === "sim" && demo) demo.checkIn();
  const nowNs = String(Date.now() * 1e6);
  simState.inheritance = { ...(simState.inheritance || {}), lastCheckin: nowNs, open: false, heirs: simState.inheritance?.heirs || (await safe(() => viewC.get_heirs(), [])) };
  toast("Simulated: check-in", { detail: "Owner check-in (simulasi). Inheritance ditutup.", kind: "ok" });
  await refreshDemoViews();
});
$("act-payroll").addEventListener("click", async () => {
  try {
    if (mode === "sim" && demo) demo.runPayroll();
    else simState.payrollRunsDelta += 1;
    toast("Simulated: run payroll", { detail: "Payroll batch (eth) disimulasikan.", kind: "ok" });
  } catch (err) { toast("Payroll failed", { detail: errMsg(err), kind: "bad" }); }
  await refreshDemoViews();
});
$("act-panicoff").addEventListener("click", async () => {
  simState.panicked = false; if (demo?.state) demo.state.panicked = false; S.panicked = false;
  toast("Simulated: panic off", { detail: "Spending unfrozen (simulasi).", kind: "ok" });
  renderShield(computeHealth()); await refreshDemoViews();
});
$("act-panicon").addEventListener("click", async () => {
  simState.panicked = true; if (demo?.state) demo.state.panicked = true; S.panicked = true;
  toast("Simulated: panic on", { detail: "All spending frozen (simulasi).", kind: "ok" });
  renderShield(computeHealth()); await refreshDemoViews();
});

// Time capsule (simulated)
const capsuleForm = $("capsule-form");
if (capsuleForm) capsuleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const chain = (fd.get("chain") || "eth").toString().trim();
  const to = (fd.get("to") || "").toString().trim();
  const amount = (fd.get("amount") || "0").toString().trim();
  const minutes = Math.max(0, Number(fd.get("minutes") || 0));
  const message = (fd.get("message") || "").toString();
  if (!to || !/^\d+$/.test(amount)) return toast("Invalid capsule", { detail: "Isi alamat tujuan dan amount (wei).", kind: "bad" });
  const releaseAt = Date.now() * 1e6 + Math.round(minutes * 60 * 1e9);
  try {
    if (mode === "sim" && demo) {
      const id = demo.createCapsule({ chain, to, amount, release_at_ns: String(releaseAt), message });
      toast("Simulated: capsule created", { detail: `Capsule #${id} sealed (opens ${fmtDate(releaseAt)}).`, kind: "ok" });
    } else {
      const id = simState.nextHoldId++;
      simState.extraHolds.push({ id, h: { chain, to, amount, requested_at: Date.now() * 1e6, status: "Pending", escrow: [], capsule_release_at: releaseAt, message } });
      toast("Simulated: capsule created", { detail: `Capsule #${id} (simulasi, opens ${fmtDate(releaseAt)}).`, kind: "ok" });
    }
  } catch (err) { toast("Capsule failed", { detail: errMsg(err), kind: "bad" }); }
  await refreshDemoViews();
});

const releaseCapsuleForm = $("release-capsule-form");
if (releaseCapsuleForm) releaseCapsuleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = Number(new FormData(e.target).get("id"));
  try {
    if (mode === "sim" && demo) {
      // allow demo release even if "time" hasn't passed in wall clock by forcing if sealed past
      const h = demo.state.holds[id];
      if (h && Date.now() * 1e6 < Number(h.capsule_release_at)) {
        // simulate time passing for demo convenience
        h.capsule_release_at = Date.now() * 1e6 - 1;
      }
      demo.releaseCapsule(id);
    } else {
      const x = simState.extraHolds.find((h) => h.id === id);
      if (!x) throw new Error("capsule not found (simulated)");
      if (!(Number(x.h.capsule_release_at) > 0)) throw new Error("not a capsule");
      x.h.status = "Released";
    }
    toast("Simulated: capsule released", { detail: `Capsule #${id} released (simulasi).`, kind: "ok" });
  } catch (err) { toast("Release failed", { detail: errMsg(err), kind: "bad" }); }
  await refreshDemoViews();
});

// Payroll add employee (simulated)
const employeeForm = $("employee-form");
if (employeeForm) employeeForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const address = (fd.get("address") || "").toString().trim();
  const salary = (fd.get("salary") || "0").toString().trim();
  if (!address || !/^\d+$/.test(salary)) return toast("Invalid employee", { detail: "Isi address dan salary (wei).", kind: "bad" });
  if (mode === "sim" && demo) {
    demo.addEmployee(address, salary);
  } else {
    const cur = simState.employees || (await safe(() => viewC.get_employees(), [])) || [];
    const list = cur.map((e) => ({ ...e }));
    const ex = list.find((e) => String(e.address).toLowerCase() === address.toLowerCase());
    if (ex) { ex.salary = salary; ex.active = true; } else list.push({ address, salary, active: true });
    simState.employees = list;
  }
  toast("Simulated: employee added", { detail: `${address} — ${fmtEth(salary)} ETH/run (simulasi).`, kind: "ok" });
  await refreshDemoViews();
});

// Digital inheritance (simulated) — different from time capsule (dead-man's-switch)
const inhCheckin = $("act-inh-checkin");
if (inhCheckin) inhCheckin.addEventListener("click", async () => {
  if (mode === "sim" && demo) demo.checkIn();
  const nowNs = String(Date.now() * 1e6);
  const heirs = simState.inheritance?.heirs || (await safe(() => viewC.get_heirs(), [])) || [];
  simState.inheritance = { ...(simState.inheritance || {}), lastCheckin: nowNs, open: false, heirs };
  toast("Simulated: check-in", { detail: "Owner heartbeat tercatat; inheritance ditutup (simulasi).", kind: "ok" });
  await refreshDemoViews();
});
const inhSilent = $("act-inh-silent");
if (inhSilent) inhSilent.addEventListener("click", async () => {
  if (mode === "sim" && demo) { demo.makeOwnerSilent(); }
  const timeout = 90n * 86_400_000_000_000n; // demo/default window
  const past = String(Date.now() * 1e6 - Number(timeout + 86_400_000_000_000n));
  const heirs = simState.inheritance?.heirs || (mode === "sim" ? demo?.state?.heirs : await safe(() => viewC.get_heirs(), [])) || [];
  simState.inheritance = { ...(simState.inheritance || {}), lastCheckin: past, open: false, heirs, timeoutNs: Number(timeout) };
  toast("Simulated: owner silent", { detail: "Waktu check-in dibuat lewat timeout (simulasi) — inheritance bisa di-claim.", kind: "warn" });
  await refreshDemoViews();
});
const inhClaim = $("act-inh-claim");
if (inhClaim) inhClaim.addEventListener("click", async () => {
  try {
    if (mode === "sim" && demo) {
      demo.claimInheritance();
    } else {
      const last = BigInt(simState.inheritance?.lastCheckin || (await safe(() => viewC.get_last_checkin())) || 0);
      const timeout = BigInt(simState.inheritance?.timeoutNs || 90n * 86_400_000_000_000n);
      const heirs = simState.inheritance?.heirs || (await safe(() => viewC.get_heirs(), [])) || [];
      if (!heirs.length) throw new Error("no heirs configured");
      if (BigInt(Date.now() * 1e6) - last < timeout) throw new Error("owner still active (simulate 'owner silent' first)");
      if (simState.inheritance?.open) throw new Error("already open");
      simState.inheritance = { ...(simState.inheritance || {}), lastCheckin: String(last), heirs, open: true };
      for (const h of heirs) simState.whitelist.add(String(h).toLowerCase());
    }
    toast("Simulated: inheritance claimed", { detail: "Estate dibuka; heirs di-whitelist (simulasi).", kind: "ok" });
  } catch (err) { toast("Claim failed", { detail: errMsg(err), kind: "bad" }); }
  await refreshDemoViews();
});
const heirForm = $("heir-form");
if (heirForm) heirForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const address = (new FormData(e.target).get("address") || "").toString().trim();
  if (!address) return toast("Enter heir address", { kind: "bad" });
  if (mode === "sim" && demo) demo.setHeirs([address]);
  const heirs = [address];
  simState.inheritance = { ...(simState.inheritance || {}), heirs, lastCheckin: simState.inheritance?.lastCheckin || (await safe(() => viewC.get_last_checkin())) || String(Date.now() * 1e6), open: false };
  toast("Simulated: heir set", { detail: `${address} (simulasi).`, kind: "ok" });
  await refreshDemoViews();
});

// ───────────────── chooser / nav ─────────────────
$("choose-sim").addEventListener("click", () => { history.replaceState(null, "", "?demo"); startMode("sim"); });
$("choose-live").addEventListener("click", () => { history.replaceState(null, "", "?mode=live"); startMode("live"); });
$("mode-switch").addEventListener("click", () => { history.replaceState(null, "", location.pathname); mode = null; ACTIVE = null; viewC = null; currentIntent = null; showModeUI(); });

$("refresh").addEventListener("click", (e) => busy(e.currentTarget, "Refreshing…", () => load().catch(console.error)));

// ───────────────── boot ─────────────────
showModeUI();
if (mode) startMode(mode);
applyRoles();

// Dev handle
if (import.meta.env.DEV) {
  window.__aegis = { startMode, S, get mode() { return mode; } };
}
