// Demo mode (?demo or ?demo=ok) — in-memory stand-in for the contract, wallet and Sepolia RPC,
// so the dashboard can be explored (and screenshotted) without a wallet or a deployed contract.
// Never loaded in production unless the URL asks for it.
const Y = (near) => (BigInt(Math.round(near * 1e6)) * 10n ** 12n).toString();
const DAY = 86_400_000_000_000;

export function createDemo({ healthy = false } = {}) {
  const operator = "aegis-ops.testnet";
  const me = operator;
  const now = () => Date.now() * 1e6;
  const state = {
    panicked: false,
    whitelist: new Set(["0x7a250d5630b4cf539739df2c5dacb4c659f2488d"]),
    nonce: 3,
    holds: {
      1: { chain: "eth", to: "0xabc0000000000000000000000000000000000001", amount: Y(0.001), requested_at: now() - 2 * DAY, status: { Cleared: { release_at: now() + 0.4 * DAY } }, escrow: ["aegis-guard1.testnet", "aegis-guard2.testnet"], capsule_release_at: 0, message: "" },
      2: { chain: "eth", to: "0x00000000000000000000000000000000000beef", amount: Y(0.05), requested_at: now() - 0.2 * DAY, status: "Pending", escrow: [], capsule_release_at: 0, message: "" },
      3: { chain: "eth", to: "0x1234567890abcdef1234567890abcdef12345678", amount: Y(1), requested_at: now() - 30 * DAY, status: "Pending", escrow: [], capsule_release_at: now() + 120 * DAY, message: "Happy 18th!" },
    },
  };
  const verdicts = {};

  function scoreMemo(memo = "") {
    const m = String(memo).toLowerCase();
    const risky = /(seed|phrase|private key|verify|migration|airdrop|claim now|urgent|support)/.test(m);
    return risky ? { risk: 100, denied: true, reason: "phishing-like request detected" } : { risk: 5, denied: false, reason: "no obvious risk signals" };
  }

  function simulateFor(args) {
    if (state.panicked) return "Deny";
    const v = verdicts[args.intent_hash];
    if (!v) return "Deny"; // reviewer set => verdict required
    if (v.denied || v.risk >= 70) return "Deny";
    const addr = String(args.to || "").toLowerCase();
    if (state.whitelist.has(addr)) return "Approve";
    return "Hold";
  }

  const viewC = {
    async get_operator() { return operator; },
    async get_policy() {
      return { daily_limits: { eth: healthy ? "10000000000000000" : "2000000000000000000000000" }, verdict_ttl: String(600_000_000_000), quiet_period: String(DAY), guard_threshold: 2, known_grace: String(30 * DAY), panic_cooldown: String(3 * DAY) };
    },
    async get_reviewer() { return "aegis-reviewer.testnet"; },
    async get_guardians() { return ["aegis-guard1.testnet", "aegis-guard2.testnet"]; },
    async is_panicked() { return state.panicked; },
    async get_nonce() { return state.nonce; },
    async compute_intent_hash() { return null; }, // let UI compute fallback
    async get_ai_verdict({ intent_hash }) { return verdicts[intent_hash] ?? null; },
    async get_hold({ id }) { return state.holds[id] ?? null; },
    async simulate_tx(args) { return simulateFor({ ...args, intent_hash: args.intent_hash || null }); },
    async is_whitelisted({ address }) { return state.whitelist.has(String(address).toLowerCase()); },
    async get_last_checkin() { return String(now() - 12 * DAY); },
    async get_heirs() { return ["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]; },
    async is_inheritance_open() { return false; },
    async get_employees() { return [{ address: "0xa1…c4", salary: Y(0.1), active: true }, { address: "0xb2…9e", salary: Y(0.2), active: true }]; },
    async get_payroll_runs() { return 1; },
    async get_admin_proposals() { return [["daily_limit:eth", "10000000000000000", String(now() - 0.5 * DAY)]]; },
    async get_admin_delay() { return String(DAY); },
  };

  function submitVerdict(intentHash, memo) {
    const s = scoreMemo(memo);
    verdicts[intentHash] = { intent_hash: intentHash, risk: s.risk, denied: s.denied, model: "demo-sim", reason: s.reason, reviewed_at: String(now()) };
    return verdicts[intentHash];
  }
  function evaluate(intent) {
    const decision = simulateFor({ ...intent, intent_hash: intent.ih });
    if (decision === "Approve" || decision === "Hold" || decision === "Deny") state.nonce += 1;
    return { decision, verdict: verdicts[intent.ih] ?? null };
  }

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const wallet = {
    async signAndSendTransaction({ actions }) {
      await wait(300);
      const name = actions?.[0]?.functionCall?.methodName ?? actions?.[0]?.params?.methodName ?? "tx";
      if (name === "panic_on") state.panicked = true;
      if (name === "panic_off") state.panicked = false;
      return { transaction: { hash: `DEMO${name.slice(0, 6).toUpperCase()}${Date.now().toString(36)}` } };
    },
  };

  return {
    viewC, wallet, me, operator, state,
    ethBalance: 190000000000000000n,
    ethAddress: "0x000000000000000000000000000000000000dEaD",
    submitVerdict, evaluate, scoreMemo,
  };
}
