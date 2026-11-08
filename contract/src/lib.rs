//! Watchdog Wallet — a policy engine that guards cross-chain spending.
//!
//! An owner's NEAR account controls the wallet's addresses on external chains
//! (Bitcoin / Ethereum) through NEAR Chain Signatures. Every outbound transfer
//! must be replayed to this contract before it is signed: `evaluate_tx` returns
//! an explicit decision, and only approved transfers are ever signed.
//!
//! Rules (all readable by anyone):
//! - `daily_limit`  — max spend per UTC day across all chains.
//! - `whitelist`    — addresses added by the owner skip the quiet period.
//! - `quiet_period` — transfers to a first-seen address are held for N seconds.
//! - `panic_mode`   — any guardian can freeze *everything*; only the owner
//!                    can unfreeze, after a mandatory cooldown.
//!
//! Holds can be escalated by guardians (M-of-N) to force a release, but the
//! owner can cancel any hold until it is executed.

use near_sdk::json_types::U128;
use near_sdk::serde::{de::DeserializeOwned, Serialize};
use near_sdk::serde_json;
use near_sdk::store::{IterableMap, LookupMap};
use near_sdk::{env, log, near, require, AccountId};
use std::collections::HashMap;

pub const ONE_DAY_NANO: u64 = 86_400_000_000_000;
/// Mandatory cooldown before panic mode can be turned off.
pub const PANIC_COOLDOWN_NANO: u64 = 3 * ONE_DAY_NANO;
/// The admin timelock can never be configured below this floor (V1).
pub const MIN_ADMIN_DELAY_NANO: u64 = 300_000_000_000; // 5 minutes
/// ...and never above this ceiling, so a stolen key cannot lock admin forever.
pub const MAX_ADMIN_DELAY_NANO: u64 = 30 * ONE_DAY_NANO;

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Sign it.
    Approve,
    /// Held for the quiet period; helds can be cancelled by the
    /// owner and escalated by guardians.
    Hold,
    /// Rejected outright — the transfer must never be signed.
    Deny,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HoldStatus {
    /// Waiting out the quiet period; owner can cancel, guardians can escalate.
    Pending,
    /// Guardians reached the threshold; executes once `release_at` passes.
    /// The owner can still cancel until then.
    Cleared { release_at: u64 },
    /// Executed — funds were signed out.
    Released,
    /// Cancelled by the owner before release.
    Cancelled,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Hold {
    pub chain: String,
    pub to: String,
    pub amount: U128,
    pub requested_at: u64,
    pub status: HoldStatus,
    /// Guardian accounts that escalated, and height of that threshold.
    pub escrow: Vec<AccountId>,
    /// Time-capsule: 0 = ordinary hold; >0 = cannot be released before
    /// this timestamp (ns). Release is permissionless after that.
    pub capsule_release_at: u64,
    /// Optional message attached (e.g. capsule letter). Empty = none.
    pub message: String,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Employee {
    pub address: String,
    /// Salary per payroll run (wei-equivalent units).
    pub salary: U128,
    pub active: bool,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct AiVerdict {
    /// 0 = safe … 100 = malicious.
    pub risk: u8,
    /// Hard "no" from the reviewer — denies the transfer even if whitelisted.
    pub denied: bool,
    /// Model / agent that produced the verdict (for display + audit).
    pub model: String,
    pub reviewed_at: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Policy {
    /// Spend cap per UTC day per *bucket*, in that chain's own smallest unit
    /// (wei for EVM chains, sats for BTC). Every EVM label shares the `eth`
    /// bucket; every unlisted label shares `other` (which starts at 0 = deny).
    pub daily_limits: HashMap<String, U128>,
    /// First-seen addresses are held for this long.
    pub quiet_period: u64,
    /// Guardians needed to clear a held transfer.
    pub guard_threshold: u32,
    /// A first-seen address can be re-evaluated without re-holding for this long.
    pub known_grace: u64,
    /// Mandatory cooldown before panic mode can be turned off.
    /// Default 3 days; changes are timelocked (propose/apply).
    pub panic_cooldown: u64,
    /// AI verdicts expire this long after `reviewed_at` (ns). Default 10 min.
    pub verdict_ttl: u64,
}

/// Default AI gate: score >= this, or an explicit `denied`, blocks the tx.
pub const AI_DENY_THRESHOLD: u8 = 70;

impl Policy {
    /// Daily spend limit for the bucket that owns `chain`. Chains without an
    /// explicit bucket fall into `other`, whose default limit is 0 (deny).
    pub fn limit_for(&self, chain: &str) -> u128 {
        self.daily_limits
            .get(&chain_bucket(chain))
            .map(|l| l.0)
            .unwrap_or(0)
    }
}

const EVM_CHAINS: &[&str] = &[
    "eth", "ethereum", "base", "arb", "arbitrum", "op", "optimism", "polygon", "matic", "bsc", "bnb", "avax", "zksync",
];

/// Bucket a chain label into a shared spend counter (N2/V4): all EVM labels
/// share the `eth` counter, all Bitcoin aliases share `btc`, and every
/// unlisted label shares `other` — so relabeling cannot multiply the limit.
fn chain_bucket(chain: &str) -> String {
    let c = chain.to_lowercase();
    if EVM_CHAINS.contains(&c.as_str()) {
        "eth".to_string()
    } else if c == "btc" || c == "bitcoin" {
        "btc".to_string()
    } else {
        "other".to_string()
    }
}

/// Labels and destinations are validated before they enter an action key or a
/// payload (V8): no delimiters, whitespace, or control characters.
fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn valid_address(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Payloads are JSON, not delimiter-joined strings (V8): a `|` or `,` inside a
/// value can never change which value is applied after the timelock.
fn pack<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| env::panic_str("payload encode failed"))
}

fn unpack<T: DeserializeOwned>(payload: &str) -> T {
    serde_json::from_str(payload).unwrap_or_else(|_| env::panic_str("bad payload"))
}

fn intent_hash_for(chain: &str, to: &str, amount: u128, memo_hash: &str, nonce: u64) -> String {
    // Length-prefixed borsh tuple (N9): no delimiter collisions.
    use near_sdk::borsh::BorshSerialize;
    let mut v = Vec::new();
    BorshSerialize::serialize(
        &(chain.to_lowercase(), to.to_lowercase(), amount, memo_hash.to_lowercase(), nonce),
        &mut v,
    )
    .unwrap();
    env::sha256(&v)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[near(contract_state)]
pub struct Watchdog {
    /// Account allowed to submit real outbound transfers (the wallet account).
    operator: AccountId,
    /// Trusted AI reviewer — runs off-chain (NEAR AI / TEE), attests here.
    reviewer: Option<AccountId>,
    ai_deny_threshold: u8,
    /// intent_hash -> latest AI verdict.
    verdicts: IterableMap<String, AiVerdict>,
    policy: Policy,
    whitelisted: IterableMap<String, u64>,
    guardian: IterableMap<AccountId, bool>,
    /// (chain, lowercased address) -> last seen nanosecond timestamp.
    seen: IterableMap<String, u64>,
    holds: IterableMap<u64, Hold>,
    next_hold_id: u64,
    /// (UTC day, chain) -> amount spent so far that day.
    spent: LookupMap<String, u128>,
    panic: bool,
    panic_started_at: u64,
    /// Incremented on every evaluate_tx so each verdict binds to one transfer.
    next_nonce: u64,
    /// Admin timelock: action -> proposed_at (ns). See propose_*/apply_*.
    admin_pending: IterableMap<String, u64>,
    /// Action -> payload (string-encoded; see propose fns).
    admin_payload: LookupMap<String, String>,
    /// Delay before a timelocked admin change applies (default 1 day).
    pub admin_delay: u64,
    /// Pre-approved transfers: "chain|to|amount" -> true.
    /// Populated by release_hold (Cleared) and release_capsule; consumed by
    /// evaluate_tx (single use).
    preapproved: LookupMap<String, bool>,
    /// Inheritance heirs: NEAR accounts that may call claim_inheritance...
    heir_accounts: Vec<AccountId>,
    /// ...and their payout addresses (chain "eth") whitelisted while open.
    heir_addresses: Vec<String>,
    /// Guardian votes to open the inheritance (M-of-N, like holds).
    heir_votes: IterableMap<AccountId, bool>,
    /// Guardian votes to veto pending admin actions (N3: counted per
    /// guardian — "action:account" — never twice by the same guardian).
    veto_votes: IterableMap<String, bool>,
    /// Whitelist entries created by an open inheritance (V7). Removed on
    /// check_in so heir access ends with the estate; owner entries stay.
    heir_whitelisted: IterableMap<String, bool>,
    /// After panic_off, panic_on re-arms only after this (default 1 hour).
    last_panic_off: u64,
    // --- inheritance --------------------------------------------------
    /// Last time the operator checked in (ns). Genesis = init time.
    last_checkin: u64,
    /// Silence after which the estate may be opened (default 90d).
    inheritance_timeout: u64,
    inheritance_open: bool,
    // --- payroll ------------------------------------------------------
    employees: IterableMap<String, Employee>,
    payroll_runs: u64,
}

impl Default for Watchdog {
    fn default() -> Self {
        env::panic_str("contract must be initialized with new()")
    }
}

#[near]
impl Watchdog {
    #[init]
    pub fn new(operator: AccountId, guard_threshold: u32) -> Self {
        Self::init_base(operator, guard_threshold)
    }

    /// One-shot bootstrap for production deployments: the initial reviewer,
    /// guardians, whitelist, and admin delay are set atomically at init, so no
    /// post-init setter is needed (V1). The delay is floored at 5 minutes and
    /// can never be lowered instantly afterwards.
    #[init]
    pub fn new_configured(
        operator: AccountId,
        guard_threshold: u32,
        admin_delay: u64,
        reviewer: Option<AccountId>,
        guardians: Vec<AccountId>,
        whitelist: Vec<(String, String)>,
    ) -> Self {
        require!(admin_delay >= MIN_ADMIN_DELAY_NANO, "admin delay below minimum");
        require!(admin_delay <= MAX_ADMIN_DELAY_NANO, "admin delay above maximum");
        require!(
            guardians.len() as u32 >= guard_threshold,
            "threshold exceeds guardian count"
        );
        let mut s = Self::init_base(operator, guard_threshold);
        s.admin_delay = admin_delay;
        s.reviewer = reviewer;
        for guardian in guardians {
            s.guardian.insert(guardian, true);
        }
        // H6: the map dedupes, so the pre-insert length check is not enough.
        // Re-check against the stored guardians or `[a, a]` with threshold 2
        // would initialize with a single guardian and holds could never clear.
        require!(
            s.guardian.len() as u32 >= guard_threshold,
            "threshold exceeds unique guardian count"
        );
        for (chain, address) in whitelist {
            require!(valid_label(&chain), "bad chain label");
            require!(valid_address(&address), "bad address");
            s.whitelisted.insert(
                format!("{}:{}", chain.to_lowercase(), address.to_lowercase()),
                env::block_timestamp(),
            );
        }
        s
    }

    fn init_base(operator: AccountId, guard_threshold: u32) -> Self {
        require!(guard_threshold >= 1, "threshold must be >= 1");
        Self {
            operator,
            reviewer: None,
            ai_deny_threshold: AI_DENY_THRESHOLD,
            verdicts: IterableMap::new(b"v"),
            policy: Policy {
                daily_limits: {
                    let mut m = HashMap::new();
                    m.insert("eth".to_string(), U128(10_000_000_000_000_000)); // 0.01 ETH in wei
                    m.insert("btc".to_string(), U128(1_000_000)); // 0.01 BTC in sats
                    m
                },
                quiet_period: ONE_DAY_NANO,
                guard_threshold,
                known_grace: 30 * ONE_DAY_NANO,
                panic_cooldown: PANIC_COOLDOWN_NANO,
                verdict_ttl: 600_000_000_000, // 10 minutes
            },
            whitelisted: IterableMap::new(b"w".as_slice()),
            guardian: IterableMap::new(b"g".as_slice()),
            seen: IterableMap::new(b"s".as_slice()),
            holds: IterableMap::new(b"h"),
            next_hold_id: 1,
            spent: LookupMap::new(b"d"),
            panic: false,
            panic_started_at: 0,
            next_nonce: 1,
            admin_pending: IterableMap::new(b"ap".as_slice()),
            admin_payload: LookupMap::new(b"aq".as_slice()),
            admin_delay: ONE_DAY_NANO,
            preapproved: LookupMap::new(b"p"),
            heir_accounts: Vec::new(),
            heir_addresses: Vec::new(),
            heir_votes: IterableMap::new(b"hv".as_slice()),
            veto_votes: IterableMap::new(b"vv".as_slice()),
            heir_whitelisted: IterableMap::new(b"hw".as_slice()),
            last_panic_off: 0,
            last_checkin: env::block_timestamp(),
            inheritance_timeout: 90 * ONE_DAY_NANO,
            inheritance_open: false,
            employees: IterableMap::new(b"e"),
            payroll_runs: 0,
        }
    }

    // ------------------------------------------------------------------
    // Core: every outbound transfer replays here before being signed.
    // ------------------------------------------------------------------

    /// Decide on an outbound transfer. Only the wallet account (operator) may
    /// call this, so decisions can't be forged; denial/approval is signed off
    /// by the contract via events.
    ///
    /// The verdict key is computed on-chain from
    /// (chain, to, amount, memo_hash, nonce) — callers cannot invent it.
    /// `memo_hash` is the hex sha256 of the memo text (off-chain), `nonce`
    /// must equal `get_nonce()` at evaluation time.
    pub fn evaluate_tx(
        &mut self,
        chain: String,
        to: String,
        amount: U128,
        memo_hash: String,
        nonce: u64,
    ) -> Decision {
        require!(env::predecessor_account_id() == self.operator, "only operator");
        require!(nonce == self.next_nonce, "stale nonce");
        let to_norm = to.to_lowercase();

        if self.panic {
            Self::event("DENY_ALWAYS", &chain, &to_norm, amount.0);
            return Decision::Deny;
        }

        let address_key = format!("{}:{}", chain.to_lowercase(), to_norm);
        let now = env::block_timestamp();

        // --- rule: daily limit -------------------------------------------
        let day = now / ONE_DAY_NANO;
        let day_key = format!("{}|{}", day, chain_bucket(&chain));
        let used = *self.spent.get(&day_key).unwrap_or(&0);
        if used.saturating_add(amount.0) > self.policy.limit_for(&chain) {
            Self::event("DENY_DAILY_LIMIT", &chain, &to_norm, amount.0);
            return Decision::Deny;
        }

        // --- rule: AI review gate (bound, single-use, expiring) -----------
        let verdict_key = intent_hash_for(&chain, &to_norm, amount.0, &memo_hash, nonce);
        if let Some(verdict) = self.verdicts.get(&verdict_key).cloned() {
            let expired = now.saturating_sub(verdict.reviewed_at) > self.policy.verdict_ttl;
            if expired {
                self.verdicts.remove(&verdict_key);
                Self::event_ai(&chain, &to_norm, verdict.risk, "DENY_VERDICT_EXPIRED");
                return Decision::Deny;
            }
            if verdict.denied || verdict.risk >= self.ai_deny_threshold {
                Self::event_ai(&chain, &to_norm, verdict.risk, "DENY_AI");
                return Decision::Deny;
            }
        } else if self.reviewer.is_some() {
            Self::event_ai(&chain, &to_norm, 0, "DENY_NO_VERDICT");
            return Decision::Deny;
        }

        // --- rule: pre-approved entry (released hold / capsule) ---------
        // Vetted by guardians or by time; single use; still limit-checked.
        let pre_key = format!("{}|{}|{}", chain.to_lowercase(), to_norm, amount.0);
        if self.preapproved.remove(&pre_key).is_some() {
            // consume any verdict bound to this transfer too (N6)
            let vk = intent_hash_for(&chain, &to_norm, amount.0, &memo_hash, nonce);
            self.verdicts.remove(&vk);
            self.seen.insert(address_key.clone(), now);
            self.record_spend(&day_key, amount.0);
            self.next_nonce += 1;
            Self::event("APPROVE_PREAPPROVED", &chain, &to_norm, amount.0);
            return Decision::Approve;
        }

        // --- rule: existing open hold for this (chain, to) --------------
        // Opening a hold must never teach the contract the address is known:
        // otherwise the second evaluate_tx would approve immediately.
        if self.holds.values().any(|h| h.chain.to_lowercase() == chain.to_lowercase()
            && h.to == to_norm
            && (h.status == HoldStatus::Pending || holds_cleared(&h.status)))
        {
            Self::event("HOLD_EXISTS", &chain, &to_norm, amount.0);
            return Decision::Hold;
        }

        // --- rule: first-seen address -> hold for the quiet period --------
        let first_seen = self.seen.get(&address_key).copied();
        let known = matches!(first_seen, Some(t) if now.saturating_sub(t) <= self.policy.known_grace)
            || self.whitelisted.contains_key(&address_key);
        if known {
            self.seen.insert(address_key.clone(), now);
            self.record_spend(&day_key, amount.0);
            self.verdicts.remove(&verdict_key); // single-use: consumed on approve
            self.next_nonce += 1;
            Self::event("APPROVE", &chain, &to_norm, amount.0);
            return Decision::Approve;
        }

        // First interaction with this address: open a hold instead.
        let id = self.next_hold_id;
        self.next_hold_id += 1;
        self.holds.insert(
            id,
            Hold {
                chain,
                to: to_norm,
                amount,
                requested_at: now,
                status: HoldStatus::Pending,
                escrow: Vec::new(),
                capsule_release_at: 0,
                message: String::new(),
            },
        );
        Self::event_hold("HOLD_OPENED", id, 0);
        Decision::Hold
    }

    /// Called once an approved transfer has actually been broadcast.
    pub fn confirm_broadcast(&mut self) {
        require!(env::predecessor_account_id() == self.operator, "only operator");
        Self::event("BROADCAST_CONFIRMED", "", "", 0);
    }

    // ------------------------------------------------------------------
    // Time capsule — funds locked until a date (e.g. a child's 18th)
    // ------------------------------------------------------------------

    /// Release a hold once it is eligible:
    /// - `Cleared` once `release_at` has passed, or
    /// - `Pending` once the quiet period since `requested_at` has elapsed.
    /// Only then is the address marked seen and the spend recorded —
    /// evaluating again before release keeps returning Hold.
    pub fn release_hold(&mut self, id: u64) {
        self.only_operator();
        let quiet = self.policy.quiet_period;
        let hold = self.hold_mut(id);
        require!(hold.capsule_release_at == 0, "not a plain hold");
        let now = env::block_timestamp();
        let eligible = match &hold.status {
            HoldStatus::Cleared { release_at } => now >= *release_at,
            HoldStatus::Pending => now.saturating_sub(hold.requested_at) >= quiet,
            _ => false,
        };
        require!(eligible, "hold not yet releasable");
        let (chain, to, amount) = (hold.chain.clone(), hold.to.clone(), hold.amount);
        hold.status = HoldStatus::Released;
        // The released hold becomes a single-use pre-approved entry (F6):
        // evaluate_tx will approve exactly this (chain, to, amount) once
        // and record the spend there — NOT here (N4 double-count).
        self.preapproved.insert(format!("{}|{}|{}", chain.to_lowercase(), to, amount.0), true);
        let address_key = format!("{}:{}", chain.to_lowercase(), to);
        self.seen.insert(address_key, now);
        Self::event_hold("HOLD_RELEASED", id, 0);
    }

    /// Seal a capsule: funds are earmarked until `release_at` (ns) and
    /// cannot be released before then, by anyone. After that, release is
    /// permissionless. The owner can cancel before release, like any hold.
    pub fn create_capsule(
        &mut self,
        chain: String,
        to: String,
        amount: U128,
        release_at: u64,
        message: String,
    ) -> u64 {
        self.only_operator();
        require!(valid_label(&chain), "bad chain label");
        require!(valid_address(&to), "bad address");
        let now = env::block_timestamp();
        require!(release_at > now, "release_at must be future");
        // V3: a sealed capsule may not open before the quiet period, so a
        // stolen key cannot create+release one instantly to skip the hold.
        require!(
            release_at >= now.saturating_add(self.policy.quiet_period),
            "capsule lock must be at least the quiet period"
        );
        let id = self.next_hold_id;
        self.next_hold_id += 1;
        self.holds.insert(
            id,
            Hold {
                chain,
                to: to.to_lowercase(),
                amount,
                requested_at: now,
                status: HoldStatus::Pending,
                escrow: Vec::new(),
                capsule_release_at: release_at,
                message,
            },
        );
        Self::event_hold("CAPSULE_SEALED", id, release_at);
        id
    }

    /// Release a sealed capsule once its date has passed. Permissionless —
    /// the time lock, not the caller, is the security.
    pub fn release_capsule(&mut self, id: u64) {
        let panicked = self.panic;
        let hold = self.hold_mut(id);
        require!(hold.capsule_release_at > 0, "not a capsule");
        require!(hold.status == HoldStatus::Pending, "capsule not pending");
        require!(!panicked, "panic mode");
        require!(env::block_timestamp() >= hold.capsule_release_at, "capsule still sealed");
        let key = format!("{}|{}|{}", hold.chain.to_lowercase(), hold.to, hold.amount.0);
        let address_key = format!("{}:{}", hold.chain.to_lowercase(), hold.to);
        hold.status = HoldStatus::Released;
        // Released capsule = pre-approved entry consumed by evaluate_tx (F6).
        self.preapproved.insert(key, true);
        // V3: the destination becomes known only after the sealed period has
        // elapsed (same rule as a released hold), never at seal time.
        self.seen.insert(address_key, env::block_timestamp());
        Self::event_hold("CAPSULE_RELEASED", id, 0);
    }

    // ------------------------------------------------------------------
    // Admin timelock (F4) — sensitive changes take effect only after
    // `admin_delay`; guardians can veto while the timer runs.
    // ------------------------------------------------------------------

    const MIN_PANIC_COOLDOWN: u64 = 300_000_000_000; // 5 minutes

    fn admin_propose(&mut self, action: &str, payload: String) {
        self.only_operator();
        // A new proposal starts with zero vetoes (V2): stale votes can never
        // be pre-loaded to veto a future proposal on its first call.
        let prefix = format!("{}:", action);
        let stale: Vec<String> = self
            .veto_votes
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for k in stale {
            self.veto_votes.remove(&k);
        }
        self.admin_pending.insert(action.to_string(), env::block_timestamp());
        self.admin_payload.insert(action.to_string(), payload.clone());
        // V5: the payload is public, in the event and in get_admin_payload,
        // so guardians can tell a harmless proposal from a malicious one.
        Self::event("ADMIN_PROPOSED", action, &payload, 0);
    }

    fn admin_take(&mut self, action: &str) -> String {
        let proposed = self
            .admin_pending
            .get(action)
            .copied()
            .unwrap_or_else(|| env::panic_str("no pending change"));
        require!(env::block_timestamp() >= proposed + self.admin_delay, "timelock not elapsed");
        self.admin_pending.remove(action);
        for k in self
            .veto_votes
            .keys()
            .filter(|k| k.starts_with(&format!("{}:", action)))
            .map(|k| k.clone())
            .collect::<Vec<_>>()
        {
            self.veto_votes.remove(&k);
        }
        self.admin_payload.remove(action).unwrap_or_else(|| env::panic_str("missing payload"))
    }

    pub fn guardian_veto(&mut self, action: String) {
        require!(self.guardian.contains_key(&env::predecessor_account_id()), "not a guardian");
        // A guardian cannot veto their own removal proposal (N3).
        let own_removal = action.starts_with(&format!("guardian_remove:{}", env::predecessor_account_id()));
        require!(!own_removal, "cannot veto own removal");
        // V2: votes only exist against a live proposal — no pre-loading.
        require!(self.admin_pending.contains_key(&action), "no pending change");
        let caller = env::predecessor_account_id();
        let key = format!("{}:{}", action, caller);
        require!(!self.veto_votes.contains_key(&key), "already voted");
        self.veto_votes.insert(key, true);
        let count = self
            .veto_votes
            .keys()
            .filter(|k| k.starts_with(&format!("{}:", action)))
            .count();
        if count >= self.policy.guard_threshold as usize {
            self.admin_pending.remove(&action);
            self.admin_payload.remove(&action);
            // votes cleared with the action — re-proposals start fresh
            let keys: Vec<String> = self
                .veto_votes
                .keys()
                .filter(|k| k.starts_with(&format!("{}:", action)))
                .cloned()
                .collect();
            for k in &keys {
                self.veto_votes.remove(k);
            }
            Self::event("ADMIN_VETOED", "", &action, count as u128);
        }
    }

    pub fn get_veto_votes(&self, action: String) -> u32 {
        self.veto_votes
            .keys()
            .filter(|k| k.starts_with(&format!("{}:", action)))
            .count() as u32
    }

    // -- admin guardrails recap (F4) ------------------------------------
    pub fn get_admin_pending(&self) -> Vec<String> {
        self.admin_pending.keys().cloned().collect()
    }

    /// V5: what a guardian is actually voting on. Payloads are JSON strings.
    pub fn get_admin_payload(&self, action: String) -> Option<String> {
        self.admin_payload.get(&action).cloned()
    }

    /// (action, payload, proposed_at) — the dashboard renders this panel.
    pub fn get_admin_proposals(&self) -> Vec<(String, String, u64)> {
        self.admin_pending
            .keys()
            .map(|action| {
                (
                    action.clone(),
                    self.admin_payload.get(action).cloned().unwrap_or_default(),
                    self.admin_pending.get(action).copied().unwrap_or(0),
                )
            })
            .collect()
    }

    pub fn get_admin_delay(&self) -> u64 {
        self.admin_delay
    }

    // -- universal timelock for ALL sensitive setters (N1/V1) -------------
    /// Instant ONLY upward. Lowering the delay must go through
    /// `propose_admin_delay` + `apply_admin_delay`, and can never reach zero —
    /// otherwise one stolen call would collapse every other timelock.
    pub fn set_admin_delay(&mut self, nanoseconds: u64) {
        self.only_operator();
        require!(nanoseconds >= MIN_ADMIN_DELAY_NANO, "admin delay below minimum");
        require!(nanoseconds <= MAX_ADMIN_DELAY_NANO, "admin delay above maximum");
        require!(
            nanoseconds >= self.admin_delay,
            "decrease is timelocked: use propose_admin_delay + apply_admin_delay"
        );
        self.admin_delay = nanoseconds;
        Self::event("ADMIN_DELAY_SET", "", "", nanoseconds as u128);
    }

    pub fn propose_admin_delay(&mut self, nanoseconds: u64) {
        require!(nanoseconds >= MIN_ADMIN_DELAY_NANO, "admin delay below minimum");
        require!(nanoseconds <= MAX_ADMIN_DELAY_NANO, "admin delay above maximum");
        self.admin_propose("admin_delay", pack(&nanoseconds));
    }

    pub fn apply_admin_delay(&mut self) {
        self.only_operator();
        let v: u64 = unpack(&self.admin_take("admin_delay"));
        require!(v >= MIN_ADMIN_DELAY_NANO, "admin delay below minimum");
        require!(v <= MAX_ADMIN_DELAY_NANO, "admin delay above maximum");
        self.admin_delay = v;
        Self::event("ADMIN_DELAY_SET", "", "", v as u128);
    }

    // -- panic cooldown (min enforced, frozen while panic is on) ----------
    pub fn propose_panic_cooldown(&mut self, nanoseconds: u64) {
        require!(!self.panic, "panic is on");
        require!(nanoseconds >= Self::MIN_PANIC_COOLDOWN, "below minimum 5m");
        self.admin_propose("panic_cooldown", pack(&nanoseconds));
    }

    pub fn apply_panic_cooldown(&mut self) {
        self.only_operator();
        require!(!self.panic, "panic is on");
        let v: u64 = unpack(&self.admin_take("panic_cooldown"));
        self.policy.panic_cooldown = v;
        Self::event("PANIC_COOLDOWN_SET", "", "", self.policy.panic_cooldown as u128);
    }

    // -- daily limit: decreases direct, increases timelocked --------------
    pub fn set_daily_limit(&mut self, chain: String, limit: U128) {
        self.only_operator();
        require!(valid_label(&chain), "bad chain label");
        let bucket = chain_bucket(&chain);
        let current = self.policy.daily_limits.get(&bucket).map(|l| l.0).unwrap_or(0);
        require!(limit.0 <= current, "increase requires timelock (propose_daily_limit)");
        self.policy.daily_limits.insert(bucket.clone(), limit);
        Self::event("DAILY_LIMIT_SET", &chain, &bucket, limit.0);
    }

    pub fn propose_daily_limit(&mut self, chain: String, limit: U128) {
        require!(valid_label(&chain), "bad chain label");
        let bucket = chain_bucket(&chain);
        let payload = pack(&(chain.to_lowercase(), bucket.clone(), limit.0));
        self.admin_propose(&format!("daily_limit:{}", bucket), payload);
    }

    pub fn apply_daily_limit(&mut self, chain: String) {
        self.only_operator();
        let bucket = chain_bucket(&chain);
        let payload = self.admin_take(&format!("daily_limit:{}", bucket));
        let (_chain, applied_bucket, amount): (String, String, u128) = unpack(&payload);
        self.policy.daily_limits.insert(applied_bucket, U128(amount));
        Self::event("DAILY_LIMIT_SET", &chain, &bucket, amount);
    }

    // -- reviewer: appointing is direct, removing is timelocked -----------
    pub fn propose_reviewer_none(&mut self) {
        self.admin_propose("reviewer_none", String::new());
    }

    pub fn apply_reviewer_none(&mut self) {
        self.only_operator();
        self.admin_take("reviewer_none");
        self.reviewer = None;
        Self::event("REVIEWER_SET", "", "", 0);
    }

    // -- guardian removal is timelocked ------------------------------------
    pub fn propose_guardian_remove(&mut self, account: AccountId) {
        self.admin_propose(&format!("guardian_remove:{}", account), account.to_string());
    }

    pub fn apply_guardian_remove(&mut self, account: AccountId) {
        self.only_operator();
        self.admin_take(&format!("guardian_remove:{}", account));
        // V6: never leave fewer guardians than the threshold, or holds could
        // never clear and the estate could never open.
        let remaining = self.guardian.len() as u32
            - if self.guardian.contains_key(&account) { 1 } else { 0 };
        require!(
            remaining >= self.policy.guard_threshold,
            "removal would drop guardians below threshold; lower the threshold first"
        );
        self.guardian.remove(&account);
        Self::event("GUARDIAN_REMOVED", "", &account.to_string(), 0);
    }

    // ------------------------------------------------------------------
    // Owner controls
    // ------------------------------------------------------------------

    pub fn cancel_hold(&mut self, id: u64) {
        require!(env::predecessor_account_id() == self.operator, "only operator");
        let hold = self.hold_mut(id);
        require!(hold.status == HoldStatus::Pending || holds_cleared(&hold.status), "hold not cancellable");
        let now = env::block_timestamp();
        if let HoldStatus::Cleared { release_at } = hold.status {
            require!(now < release_at, "waiting period already ended");
        }
        hold.status = HoldStatus::Cancelled;
        Self::event_hold("HOLD_CANCELLED", id, 0);
    }

    /// Quiet period change is timelocked (N1): quiet_period protects the
    /// first-seen rule, so shortening it must not be instant.
    pub fn propose_quiet_period_ns(&mut self, nanoseconds: u64) {
        require!(nanoseconds > 0, "must be > 0");
        self.admin_propose("quiet_period_ns", pack(&nanoseconds));
    }

    pub fn apply_quiet_period_ns(&mut self) {
        self.only_operator();
        let v: u64 = unpack(&self.admin_take("quiet_period_ns"));
        require!(v > 0, "must be > 0");
        self.policy.quiet_period = v;
        Self::event("QUIET_PERIOD_SET", "", "", self.policy.quiet_period as u128);
    }

    pub fn set_quiet_period_ns(&mut self, _nanoseconds: u64) {
        // Disabled (N1): use propose_/apply_.
        env::panic_str("timelocked: use propose_quiet_period_ns + apply_quiet_period_ns");
    }

    /// Panic cooldown change (F4): propose now, apply after the admin delay.
    /// Use `propose_panic_cooldown` / `apply_panic_cooldown`.

    // -- whitelist: timelocked (N1) -------------------------------------
    pub fn whitelist_add(&mut self, _chain: String, _address: String) {
        env::panic_str("timelocked: use propose_whitelist_add + apply_whitelist_add");
    }

    pub fn propose_whitelist_add(&mut self, chain: String, address: String) {
        require!(valid_label(&chain), "bad chain label");
        require!(valid_address(&address), "bad address");
        let c = chain.to_lowercase();
        let a = address.to_lowercase();
        self.admin_propose(&format!("whitelist_add:{}:{}", c, a), pack(&(c, a)));
    }

    pub fn apply_whitelist_add(&mut self, chain: String, address: String) {
        self.only_operator();
        require!(valid_label(&chain), "bad chain label");
        require!(valid_address(&address), "bad address");
        let c = chain.to_lowercase();
        let a = address.to_lowercase();
        // V8: the applied value comes from the call arguments (which are also
        // the action key) — never from splitting a delimiter-joined payload.
        self.admin_take(&format!("whitelist_add:{}:{}", c, a));
        self.whitelisted.insert(format!("{}:{}", c, a), env::block_timestamp());
        Self::event("WHITELIST_ADDED", &c, &a, 0);
    }

    pub fn whitelist_remove(&mut self, chain: String, address: String) {
        self.only_operator();
        require!(valid_label(&chain), "bad chain label");
        require!(valid_address(&address), "bad address");
        self.whitelisted.remove(&format!("{}:{}", chain.to_lowercase(), address.to_lowercase()));
    }

    /// Guardian adds are timelocked (N1) — a stolen owner key must not be
    /// able to install a friendly guardian instantly.
    pub fn guardian_add(&mut self, _account: AccountId) {
        env::panic_str("timelocked: use propose_guardian_add + apply_guardian_add");
    }

    pub fn propose_guardian_add(&mut self, account: AccountId) {
        self.admin_propose(&format!("guardian_add:{}", account), account.to_string());
    }

    pub fn apply_guardian_add(&mut self, account: AccountId) {
        self.only_operator();
        self.admin_take(&format!("guardian_add:{}", account));
        self.guardian.insert(account.clone(), true);
        Self::event("GUARDIAN_ADDED", "", &account.to_string(), 0);
    }

    pub fn guardian_remove(&mut self, account: AccountId) {
        // Direct removal is disabled (F4): use propose_/apply_.
        self.only_operator();
        require!(false, "use propose_guardian_remove + apply_guardian_remove");
        self.guardian.remove(&account);
    }

    // ------------------------------------------------------------------
    // Inheritance — dead-man's switch over the guarded wallet
    // ------------------------------------------------------------------

    /// Owner heartbeat. Resets the clock and closes an open inheritance.
    /// It never touches the owner's own whitelist entries (F10), and it
    /// clears stale guardian votes so a fresh emergency needs fresh votes.
    pub fn check_in(&mut self) {
        self.only_operator();
        self.last_checkin = env::block_timestamp();
        self.inheritance_open = false;
        self.heir_votes.clear();
        // V7: revoke only the whitelist entries the estate granted, never the
        // owner's own entries (F10).
        let granted: Vec<String> = self.heir_whitelisted.keys().cloned().collect();
        for key in granted {
            self.whitelisted.remove(&key);
            self.heir_whitelisted.remove(&key);
        }
        Self::event("CHECK_IN", "", "", 0);
    }

    pub fn set_heirs(&mut self, _accounts: Vec<AccountId>, _addresses: Vec<String>) {
        env::panic_str("timelocked: use propose_set_heirs + apply_set_heirs");
    }

    pub fn set_inheritance_timeout(&mut self, _nanoseconds: u64) {
        env::panic_str("timelocked: use propose_set_inheritance_timeout + apply_set_inheritance_timeout");
    }

    pub fn propose_set_heirs(&mut self, accounts: Vec<AccountId>, addresses: Vec<String>) {
        require!(!accounts.is_empty() || !addresses.is_empty(), "at least one heir");
        for address in &addresses {
            require!(valid_address(address), "bad heir address");
        }
        let payload = pack(&(accounts, addresses));
        self.admin_propose("set_heirs", payload);
    }

    pub fn apply_set_heirs(&mut self) {
        self.only_operator();
        let payload = self.admin_take("set_heirs");
        let (accs, addrs): (Vec<AccountId>, Vec<String>) = unpack(&payload);
        self.heir_accounts = accs.clone();
        self.heir_addresses = addrs;
        Self::event("HEIRS_SET", "", "", (self.heir_accounts.len() + self.heir_addresses.len()) as u128);
    }

    pub fn propose_set_inheritance_timeout(&mut self, nanoseconds: u64) {
        require!(nanoseconds > 0, "timeout must be > 0");
        self.admin_propose("set_inheritance_timeout", pack(&nanoseconds));
    }

    pub fn apply_set_inheritance_timeout(&mut self) {
        self.only_operator();
        let v: u64 = unpack(&self.admin_take("set_inheritance_timeout"));
        require!(v > 0, "timeout must be > 0");
        self.inheritance_timeout = v;
        Self::event("INHERITANCE_TIMEOUT_SET", "", "", self.inheritance_timeout as u128);
    }

    /// Open the inheritance once the operator has been silent for the
    /// timeout. Requires the guardian **threshold** (M-of-N) to vote, or a
    /// named heir account. Heir payout addresses become whitelisted (chain
    /// "eth") while the estate is open — releases still need AI verdicts
    /// and stay under the daily limit.
    pub fn claim_inheritance(&mut self) {
        let caller = env::predecessor_account_id();
        let now = env::block_timestamp();
        require!(now.saturating_sub(self.last_checkin) >= self.inheritance_timeout, "owner still active");
        require!(!self.inheritance_open, "already open");
        let is_guardian = self.guardian.contains_key(&caller);
        let is_heir = self.heir_accounts.iter().any(|h| h == &caller);
        require!(is_guardian || is_heir, "only guardian or heir");

        if is_guardian {
            self.heir_votes.insert(caller, true);
            let votes = self.heir_votes.len() as u32;
            if votes < self.policy.guard_threshold {
                Self::event("INHERITANCE_VOTE", "", "", votes as u128);
                return;
            }
        }
        self.inheritance_open = true;
        for heir in self.heir_addresses.clone() {
            let key = format!("eth:{}", heir);
            // Track only entries this estate granted; if the owner already
            // whitelisted the address, leave it untouched on check_in (F10).
            if !self.whitelisted.contains_key(&key) {
                self.whitelisted.insert(key.clone(), now);
                self.heir_whitelisted.insert(key, true);
            }
        }
        self.heir_votes.clear();
        Self::event("INHERITANCE_OPEN", "", "", self.heir_addresses.len() as u128);
    }

    // ------------------------------------------------------------------
    // Payroll — registered employees paid in batches under the same gates
    // ------------------------------------------------------------------

    pub fn add_employee(&mut self, _address: String, _salary: U128) {
        env::panic_str("timelocked: use propose_add_employee + apply_add_employee");
    }

    pub fn propose_add_employee(&mut self, address: String, salary: U128) {
        require!(valid_address(&address), "bad address");
        let key = format!("add_employee:{}", address.to_lowercase());
        self.admin_propose(&key, pack(&(address.to_lowercase(), salary.0)));
    }

    pub fn apply_add_employee(&mut self, address: String) {
        self.only_operator();
        require!(valid_address(&address), "bad address");
        let key = format!("add_employee:{}", address.to_lowercase());
        let payload = self.admin_take(&key);
        let (addr, sal): (String, u128) = unpack(&payload);
        self.employees.insert(
            addr.clone(),
            Employee {
                address: addr.clone(),
                salary: U128(sal),
                active: true,
            },
        );
        Self::event("EMPLOYEE_ADDED", "", &addr, sal);
    }

    pub fn remove_employee(&mut self, chain: String, address: String) {
        self.only_operator();
        require!(valid_label(&chain), "bad chain label");
        require!(valid_address(&address), "bad address");
        let addr = address.to_lowercase();
        let chain = chain.to_lowercase();
        self.employees.remove(&addr);
        // N10: only this employee's (chain, addr) entries are removed —
        // owner-whitelisted entries for other chains are untouched.
        self.whitelisted.remove(&format!("{}:{}", chain, addr));
        self.seen.remove(&format!("{}:{}", chain, addr));
        Self::event("EMPLOYEE_REMOVED", &chain, &addr, 0);
    }

    /// Run one payroll batch. Employees are treated like whitelisted
    /// recipients (registered by the owner), but every payment still
    /// consumes the daily limit — an oversized batch is denied as a whole
    /// if a single salary already exceeds the limit.
    pub fn run_payroll(&mut self, chain: String) -> u32 {
        self.only_operator();
        require!(!self.panic, "panic mode");
        let day = env::block_timestamp() / ONE_DAY_NANO;
        let day_key = format!("{}|{}", day, chain_bucket(&chain));
        let used = *self.spent.get(&day_key).unwrap_or(&0);

        let staff: Vec<Employee> = self.employees.values().cloned().collect();
        let total: u128 = staff.iter().map(|e| e.salary.0).sum();
        require!(used.saturating_add(total) <= self.policy.limit_for(&chain), "payroll exceeds daily limit");

        let now = env::block_timestamp();
        for emp in &staff {
            // N1: payroll does NOT whitelist — employees first-seen still
            // goes through the quiet period like everyone else.
            self.seen.insert(format!("{}:{}", chain.to_lowercase(), emp.address), now);
            // N4: do not record spend here; the per-employee evaluate_tx
            // consumes the pre-approved entry and records it exactly once.
            self.preapproved.insert(format!("{}|{}|{}", chain.to_lowercase(), emp.address, emp.salary.0), true);
        }
        self.payroll_runs += 1;
        Self::event("PAYROLL_RUN", &chain, "", staff.len() as u128);
        staff.len() as u32
    }

    // ------------------------------------------------------------------
    // AI governance — decisions of the machine, anchored on-chain
    // ------------------------------------------------------------------

    /// The reviewer runs off-chain (e.g. a model inside NEAR AI's TEE), and
    /// attests its verdict here. Only the operator may appoint one, and only
    /// the reviewer itself may submit verdicts — the operator cannot forge a
    /// "safe" score for its own transfer.
    // -- reviewer appointment is timelocked (N1) ---------------------------
    pub fn set_reviewer(&mut self, _reviewer: Option<AccountId>) {
        env::panic_str("timelocked: use propose_reviewer + apply_reviewer");
    }

    pub fn propose_reviewer(&mut self, reviewer: AccountId) {
        self.admin_propose("reviewer", pack(&reviewer.to_string()));
    }

    pub fn apply_reviewer(&mut self) {
        self.only_operator();
        let payload = self.admin_take("reviewer");
        let account: AccountId = unpack::<String>(&payload)
            .parse()
            .unwrap_or_else(|_| env::panic_str("bad payload"));
        self.reviewer = Some(account);
        Self::event("REVIEWER_SET", "", "", 0);
    }

    pub fn propose_ai_deny_threshold(&mut self, threshold: u8) {
        require!(threshold > 0 && threshold <= 100, "threshold 1..=100");
        self.admin_propose("ai_deny_threshold", pack(&threshold));
    }

    pub fn apply_ai_deny_threshold(&mut self) {
        self.only_operator();
        let v: u8 = unpack(&self.admin_take("ai_deny_threshold"));
        require!(v > 0 && v <= 100, "threshold 1..=100");
        self.ai_deny_threshold = v;
    }

    pub fn propose_guard_threshold(&mut self, threshold: u32) {
        require!(threshold >= 1, "threshold must be >= 1");
        self.admin_propose("guard_threshold", pack(&threshold));
    }

    pub fn apply_guard_threshold(&mut self) {
        self.only_operator();
        let t: u32 = unpack(&self.admin_take("guard_threshold"));
        require!(t >= 1, "threshold must be >= 1");
        require!(t <= self.guardian.len() as u32, "threshold exceeds guardian count");
        self.policy.guard_threshold = t;
        Self::event("GUARD_THRESHOLD_SET", "", "", t as u128);
    }

    pub fn set_ai_deny_threshold(&mut self, _threshold: u8) {
        env::panic_str("timelocked: use propose_ai_deny_threshold + apply_ai_deny_threshold");
    }

    /// known_grace and verdict_ttl are also timelocked (V1): increasing them
    /// instantly would let a stolen key re-arm an old address or verdict.
    pub fn set_known_grace(&mut self, _nanoseconds: u64) {
        env::panic_str("timelocked: use propose_known_grace + apply_known_grace");
    }

    pub fn propose_known_grace(&mut self, nanoseconds: u64) {
        self.admin_propose("known_grace", pack(&nanoseconds));
    }

    pub fn apply_known_grace(&mut self) {
        self.only_operator();
        let v: u64 = unpack(&self.admin_take("known_grace"));
        self.policy.known_grace = v;
        Self::event("KNOWN_GRACE_SET", "", "", v as u128);
    }

    pub fn set_verdict_ttl(&mut self, _nanoseconds: u64) {
        env::panic_str("timelocked: use propose_verdict_ttl + apply_verdict_ttl");
    }

    pub fn propose_verdict_ttl(&mut self, nanoseconds: u64) {
        require!(nanoseconds > 0, "ttl must be > 0");
        self.admin_propose("verdict_ttl", pack(&nanoseconds));
    }

    pub fn apply_verdict_ttl(&mut self) {
        self.only_operator();
        let v: u64 = unpack(&self.admin_take("verdict_ttl"));
        require!(v > 0, "ttl must be > 0");
        self.policy.verdict_ttl = v;
        Self::event("VERDICT_TTL_SET", "", "", v as u128);
    }

    /// Record a risk verdict for an intent hash (e.g. keccak256 of the tx).
    /// Resubmitting overwrites the previous verdict — the review can be
    /// corrected, but the operator must be able to see it happened.
    pub fn submit_verdict(
        &mut self,
        intent_hash: String,
        risk: u8,
        denied: bool,
        model: String,
    ) {
        let caller = env::predecessor_account_id();
        require!(self.reviewer.as_ref() == Some(&caller), "only reviewer");
        require!(risk <= 100, "risk 0..=100");
        require!(intent_hash.len() >= 8 && intent_hash.len() <= 160, "bad intent_hash");
        self.verdicts.insert(
            intent_hash,
            AiVerdict {
                risk,
                denied,
                model,
                reviewed_at: env::block_timestamp(),
            },
        );
        Self::event_ai("", "", risk, "AI_VERDICT");
    }

    // ------------------------------------------------------------------
    // Guardian powers
    // ------------------------------------------------------------------

    /// Guardians escalate a pending hold: threshold reached -> a mandatory
    /// waiting period starts, after which settlement is allowed. The owner
    /// can still cancel while the waiting period runs.
    pub fn hold_escalate(&mut self, id: u64) {
        require!(self.guardian.contains_key(&env::predecessor_account_id()), "not a guardian");
        let (threshold, quiet_period) = (self.policy.guard_threshold, self.policy.quiet_period);
        let hold = self.hold_mut(id);
        require!(hold.status == HoldStatus::Pending, "hold not pending");
        require!(hold.capsule_release_at == 0, "capsules release with time, not escalation");

        let caller = env::predecessor_account_id();
        require!(!hold.escrow.contains(&caller), "already voted");

        hold.escrow.push(caller);
        if hold.escrow.len() as u32 >= threshold {
            let release_at = env::block_timestamp() + quiet_period;
            hold.status = HoldStatus::Cleared { release_at };
            Self::event_hold("HOLD_CLEARED", id, release_at);
        } else {
            Self::event_hold("HOLD_ESCALATED", id, 0);
        }
    }

    /// Any guardian can panic-freeze all spending. After a panic is
    /// turned off, re-arming needs a 1-hour cooldown (N3).
    pub fn panic_on(&mut self) {
        require!(self.guardian.contains_key(&env::predecessor_account_id()), "not a guardian");
        if self.last_panic_off > 0 {
            require!(env::block_timestamp().saturating_sub(self.last_panic_off) >= 3_600_000_000_000, "re-panic cooldown");
        }
        if !self.panic {
            self.panic = true;
            self.panic_started_at = env::block_timestamp();
            Self::event("PANIC_ON", "", "", 0);
        }
    }

    /// Only the owner can unfreeze, and only after the mandatory cooldown —
    /// a hostile guardian cannot lock the wallet forever, but neither can a
    /// stolen owner key instantly dismiss a guardian's alarm.
    pub fn panic_off(&mut self) {
        self.only_operator();
        require!(self.panic, "panic not on");
        let elapsed = env::block_timestamp().saturating_sub(self.panic_started_at);
        require!(elapsed >= self.policy.panic_cooldown, "cooldown still running");
        self.panic = false;
        self.last_panic_off = env::block_timestamp();
        Self::event("PANIC_OFF", "", "", 0);
    }

    // ------------------------------------------------------------------
    // Views — the release rules live on-chain, anyone can read them.
    // ------------------------------------------------------------------

    pub fn get_policy(&self) -> Policy {
        self.policy.clone()
    }

    pub fn get_operator(&self) -> AccountId {
        self.operator.clone()
    }

    pub fn get_reviewer(&self) -> Option<AccountId> {
        self.reviewer.clone()
    }

    pub fn get_nonce(&self) -> u64 {
        self.next_nonce
    }

    /// The exact key evaluate_tx will look a verdict up under (agents use
    /// this; keeping the formula in the contract prevents drift).
    pub fn compute_intent_hash(
        &self,
        chain: String,
        to: String,
        amount: U128,
        memo_hash: String,
        nonce: u64,
    ) -> String {
        intent_hash_for(&chain, &to, amount.0, &memo_hash, nonce)
    }

    pub fn get_ai_verdict(&self, intent_hash: String) -> Option<AiVerdict> {
        self.verdicts.get(&intent_hash).cloned()
    }

    pub fn get_guardians(&self) -> Vec<AccountId> {
        self.guardian.keys().cloned().collect()
    }

    pub fn get_last_checkin(&self) -> u64 {
        self.last_checkin
    }

    pub fn get_heirs(&self) -> Vec<String> {
        self.heir_addresses.clone()
    }

    pub fn is_inheritance_open(&self) -> bool {
        self.inheritance_open
    }

    pub fn get_employees(&self) -> Vec<Employee> {
        self.employees.values().cloned().collect()
    }

    pub fn get_payroll_runs(&self) -> u64 {
        self.payroll_runs
    }

    pub fn is_panicked(&self) -> bool {
        self.panic
    }

    pub fn is_whitelisted(&self, chain: String, address: String) -> bool {
        self.whitelisted.contains_key(&format!("{}:{}", chain.to_lowercase(), address.to_lowercase()))
    }

    pub fn get_hold(&self, id: u64) -> Option<Hold> {
        self.holds.get(&id).cloned()
    }

    /// Dry-run a would-be transfer without side effects (frontends use this).
    pub fn simulate_tx(
        &self,
        chain: String,
        to: String,
        amount: U128,
        memo_hash: String,
        nonce: u64,
    ) -> Decision {
        let to_norm = to.to_lowercase();
        if self.panic {
            return Decision::Deny;
        }
        let day = env::block_timestamp() / ONE_DAY_NANO;
        let day_key = format!("{}|{}", day, chain_bucket(&chain));
        let used = *self.spent.get(&day_key).unwrap_or(&0);
        if used.saturating_add(amount.0) > self.policy.limit_for(&chain) {
            return Decision::Deny;
        }
        let now = env::block_timestamp();
        let verdict_key = intent_hash_for(&chain, &to_norm, amount.0, &memo_hash, nonce);
        if let Some(verdict) = self.verdicts.get(&verdict_key) {
            let expired = now.saturating_sub(verdict.reviewed_at) > self.policy.verdict_ttl;
            if expired || verdict.denied || verdict.risk >= self.ai_deny_threshold {
                return Decision::Deny;
            }
        } else if self.reviewer.is_some() {
            return Decision::Deny;
        }
        let key = format!("{}:{}", chain.to_lowercase(), to_norm);
        let first_seen = self.seen.get(&key);
        let known = matches!(first_seen, Some(t) if env::block_timestamp().saturating_sub(*t) <= self.policy.known_grace)
            || self.whitelisted.contains_key(&key);
        if known {
            Decision::Approve
        } else {
            Decision::Hold
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn only_operator(&self) {
        require!(env::predecessor_account_id() == self.operator, "only operator");
    }

    fn hold_mut(&mut self, id: u64) -> &mut Hold {
        self.holds.get_mut(&id).unwrap_or_else(|| env::panic_str("hold not found"))
    }

    fn record_spend(&mut self, day_key: &str, amount: u128) {
        let used = self.spent.get(day_key).copied().unwrap_or(0);
        self.spent.insert(day_key.to_string(), used + amount);
    }

    fn event(tag: &str, chain: &str, to: &str, amount: u128) {
        log!("watchdog:{}|{}|{}|{}", tag, chain, to, amount);
    }

    fn event_ai(chain: &str, to: &str, risk: u8, tag: &str) {
        log!("watchdog_ai:{}|{}|{}|risk={}", tag, chain, to, risk);
    }

    fn event_hold(tag: &str, id: u64, release_at: u64) {
        log!("watchdog_hold:{}|{}|{}", tag, id, release_at);
    }
}

fn holds_cleared(status: &HoldStatus) -> bool {
    matches!(status, HoldStatus::Cleared { .. })
}
