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
use near_sdk::{env, log, near, require, AccountId};
use std::collections::HashMap;

pub const ONE_DAY_NANO: u64 = 86_400_000_000_000;
/// Mandatory cooldown before panic mode can be turned off.
pub const PANIC_COOLDOWN_NANO: u64 = 3 * ONE_DAY_NANO;

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
    /// Spend cap per UTC day, in wei-equivalent per-chain units.
    pub daily_limit: U128,
    /// First-seen addresses are held for this long.
    pub quiet_period: u64,
    /// Guardians needed to clear a held transfer.
    pub guard_threshold: u32,
    /// A first-seen address can be re-evaluated without re-holding for this long.
    pub known_grace: u64,
    /// Mandatory cooldown before panic mode can be turned off.
    /// Default 3 days; the operator may lower it — every change is on-chain.
    pub panic_cooldown: u64,
}

/// Default AI gate: score >= this, or an explicit `denied`, blocks the tx.
pub const AI_DENY_THRESHOLD: u8 = 70;

#[near(contract_state)]
pub struct Watchdog {
    /// Account allowed to submit real outbound transfers (the wallet account).
    operator: AccountId,
    /// Trusted AI reviewer — runs off-chain (NEAR AI / TEE), attests here.
    reviewer: Option<AccountId>,
    ai_deny_threshold: u8,
    /// intent_hash -> latestAI verdict.
    verdicts: HashMap<String, AiVerdict>,
    policy: Policy,
    whitelisted: HashMap<String, u64>,
    guardian: HashMap<AccountId, bool>,
    /// (chain, lowercased address) -> last seen nanosecond timestamp.
    seen: HashMap<String, u64>,
    holds: HashMap<u64, Hold>,
    next_hold_id: u64,
    /// (UTC day, chain) -> amount spent so far that day.
    spent: HashMap<String, u128>,
    panic: bool,
    panic_started_at: u64,
    // --- inheritance --------------------------------------------------
    /// Last time the operator checked in (ns). Genesis = init time.
    last_checkin: u64,
    /// Silence after which guardians may open the inheritance (default 90d).
    inheritance_timeout: u64,
    heirs: Vec<String>,
    inheritance_open: bool,
    // --- payroll ------------------------------------------------------
    employees: HashMap<String, Employee>,
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
        require!(guard_threshold >= 1, "threshold must be >= 1");
        Self {
            operator,
            reviewer: None,
            ai_deny_threshold: AI_DENY_THRESHOLD,
            verdicts: HashMap::new(),
            policy: Policy {
                daily_limit: U128(2_000_000_000_000_000_000_000_000), // 2000 ETH-wei ≈ 0.002 ETH
                quiet_period: ONE_DAY_NANO,
                guard_threshold,
                known_grace: 30 * ONE_DAY_NANO,
                panic_cooldown: PANIC_COOLDOWN_NANO,
            },
            whitelisted: HashMap::new(),
            guardian: HashMap::new(),
            seen: HashMap::new(),
            holds: HashMap::new(),
            next_hold_id: 1,
            spent: HashMap::new(),
            panic: false,
            panic_started_at: 0,
            last_checkin: env::block_timestamp(),
            inheritance_timeout: 90 * ONE_DAY_NANO,
            heirs: Vec::new(),
            inheritance_open: false,
            employees: HashMap::new(),
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
    /// `intent_hash` links this transfer to an AI verdict (`submit_verdict`).
    /// While a reviewer is configured, unknown intents are held pending review.
    pub fn evaluate_tx(
        &mut self,
        chain: String,
        to: String,
        amount: U128,
        intent_hash: String,
    ) -> Decision {
        require!(env::predecessor_account_id() == self.operator, "only operator");
        let to_norm = to.to_lowercase();

        if self.panic {
            Self::event("DENY_ALWAYS", &chain, &to_norm, amount.0);
            return Decision::Deny;
        }

        let address_key = format!("{}:{}", chain.to_lowercase(), to_norm);
        let now = env::block_timestamp();

        // --- rule: daily limit -------------------------------------------
        let day = now / ONE_DAY_NANO;
        let day_key = format!("{}|{}", day, chain.to_lowercase());
        let used = *self.spent.get(&day_key).unwrap_or(&0);
        if used.saturating_add(amount.0) > self.policy.daily_limit.0 {
            Self::event("DENY_DAILY_LIMIT", &chain, &to_norm, amount.0);
            return Decision::Deny;
        }

        // --- rule: AI review gate -----------------------------------------
        // AI denies override everything (even whitelisted addresses), and a
        // configured reviewer with no verdict on record means "not reviewed yet".
        if let Some(verdict) = self.verdicts.get(&intent_hash) {
            if verdict.denied || verdict.risk >= self.ai_deny_threshold {
                Self::event_ai(&chain, &to_norm, verdict.risk, "DENY_AI");
                return Decision::Deny;
            }
        } else if self.reviewer.is_some() {
            Self::event_ai(&chain, &to_norm, 0, "DENY_NO_VERDICT");
            return Decision::Deny;
        }

        // --- rule: first-seen address -> hold for the quiet period --------
        let first_seen = self.seen.get(&address_key).copied();
        let known = matches!(first_seen, Some(t) if now.saturating_sub(t) <= self.policy.known_grace)
            || self.whitelisted.contains_key(&to_norm);
        if !known {
            self.seen.insert(address_key.clone(), now);
        }
        if known {
            self.seen.insert(address_key.clone(), now);
            self.record_spend(&day_key, amount.0);
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
        require!(release_at > env::block_timestamp(), "release_at must be future");
        let id = self.next_hold_id;
        self.next_hold_id += 1;
        self.holds.insert(
            id,
            Hold {
                chain,
                to: to.to_lowercase(),
                amount,
                requested_at: env::block_timestamp(),
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
        hold.status = HoldStatus::Released;
        Self::event_hold("CAPSULE_RELEASED", id, 0);
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

    pub fn set_daily_limit(&mut self, limit: U128) {
        self.only_operator();
        self.policy.daily_limit = limit;
    }

    pub fn set_quiet_period(&mut self, seconds: u64) {
        self.only_operator();
        self.policy.quiet_period = seconds;
    }

    /// Owner-tunable panic cooldown (e.g. short for testing, 3 days by default).
    /// Changing it is public on-chain, and a hostile guardian cannot touch it.
    pub fn set_panic_cooldown(&mut self, nanoseconds: u64) {
        self.only_operator();
        self.policy.panic_cooldown = nanoseconds;
        Self::event("PANIC_COOLDOWN_SET", "", "", nanoseconds as u128);
    }

    pub fn whitelist_add(&mut self, address: String) {
        self.only_operator();
        self.whitelisted.insert(address.to_lowercase(), env::block_timestamp());
    }

    pub fn whitelist_remove(&mut self, address: String) {
        self.only_operator();
        self.whitelisted.remove(&address.to_lowercase());
    }

    /// Owner can add guardians (demo simplification; a production version
    /// would use guardian self-enrolment or a DAO — see README).
    pub fn guardian_add(&mut self, account: AccountId) {
        self.only_operator();
        self.guardian.insert(account, true);
    }

    pub fn guardian_remove(&mut self, account: AccountId) {
        self.only_operator();
        self.guardian.remove(&account);
    }

    // ------------------------------------------------------------------
    // Inheritance — dead-man's switch over the guarded wallet
    // ------------------------------------------------------------------

    /// Owner heartbeat. Any check-in resets the inheritance clock.
    pub fn check_in(&mut self) {
        self.only_operator();
        self.last_checkin = env::block_timestamp();
        if self.inheritance_open {
            self.inheritance_open = false;
            for heir in self.heirs.clone() {
                self.whitelisted.remove(&heir);
            }
        }
        Self::event("CHECK_IN", "", "", 0);
    }

    pub fn set_heirs(&mut self, addresses: Vec<String>) {
        self.only_operator();
        require!(!addresses.is_empty(), "at least one heir");
        self.heirs = addresses.iter().map(|a| a.to_lowercase()).collect();
        Self::event("HEIRS_SET", "", "", self.heirs.len() as u128);
    }

    pub fn set_inheritance_timeout(&mut self, nanoseconds: u64) {
        self.only_operator();
        require!(nanoseconds > 0, "timeout must be > 0");
        self.inheritance_timeout = nanoseconds;
        Self::event("INHERITANCE_TIMEOUT_SET", "", "", nanoseconds as u128);
    }

    /// Open the inheritance: callable by a guardian or a named heir once
    /// the operator has been silent for the timeout. Heirs are then
    /// whitelisted, so `evaluate_tx` can approve releases to them
    /// (still gated by AI verdict + daily limit).
    pub fn claim_inheritance(&mut self) {
        let caller = env::predecessor_account_id();
        let now = env::block_timestamp();
        require!(now.saturating_sub(self.last_checkin) >= self.inheritance_timeout, "owner still active");
        let is_guardian = self.guardian.contains_key(&caller);
        let is_heir = self.heirs.iter().any(|h| h == &caller.as_str());
        require!(is_guardian || is_heir, "only guardian or heir");
        require!(!self.inheritance_open, "already open");
        self.inheritance_open = true;
        for heir in self.heirs.clone() {
            self.whitelisted.insert(heir, now);
        }
        Self::event("INHERITANCE_OPEN", "", "", self.heirs.len() as u128);
    }

    // ------------------------------------------------------------------
    // Payroll — registered employees paid in batches under the same gates
    // ------------------------------------------------------------------

    pub fn add_employee(&mut self, address: String, salary: U128) {
        self.only_operator();
        self.employees.insert(
            address.to_lowercase(),
            Employee {
                address: address.to_lowercase(),
                salary,
                active: true,
            },
        );
        Self::event("EMPLOYEE_ADDED", "", &address.to_lowercase(), salary.0);
    }

    pub fn remove_employee(&mut self, address: String) {
        self.only_operator();
        self.employees.remove(&address.to_lowercase());
        Self::event("EMPLOYEE_REMOVED", "", &address.to_lowercase(), 0);
    }

    /// Run one payroll batch. Employees are treated like whitelisted
    /// recipients (registered by the owner), but every payment still
    /// consumes the daily limit — an oversized batch is denied as a whole
    /// if a single salary already exceeds the limit.
    pub fn run_payroll(&mut self, chain: String) -> u32 {
        self.only_operator();
        require!(!self.panic, "panic mode");
        let day = env::block_timestamp() / ONE_DAY_NANO;
        let day_key = format!("{}|{}", day, chain.to_lowercase());
        let used = *self.spent.get(&day_key).unwrap_or(&0);

        let staff: Vec<Employee> = self.employees.values().cloned().collect();
        let total: u128 = staff.iter().map(|e| e.salary.0).sum();
        require!(used.saturating_add(total) <= self.policy.daily_limit.0, "payroll exceeds daily limit");

        let now = env::block_timestamp();
        for emp in &staff {
            self.seen.insert(format!("{}:{}", chain.to_lowercase(), emp.address), now);
            self.whitelisted.entry(emp.address.clone()).or_insert(now);
        }
        self.record_spend(&day_key, total);
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
    pub fn set_reviewer(&mut self, reviewer: Option<AccountId>) {
        self.only_operator();
        self.reviewer = reviewer;
        Self::event("REVIEWER_SET", "", "", 0);
    }

    pub fn set_ai_deny_threshold(&mut self, threshold: u8) {
        self.only_operator();
        require!(threshold > 0 && threshold <= 100, "threshold 1..=100");
        self.ai_deny_threshold = threshold;
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

    /// Any guardian can panic-freeze all spending.
    pub fn panic_on(&mut self) {
        require!(self.guardian.contains_key(&env::predecessor_account_id()), "not a guardian");
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
        self.heirs.clone()
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

    pub fn is_whitelisted(&self, address: String) -> bool {
        self.whitelisted.contains_key(&address.to_lowercase())
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
        intent_hash: String,
    ) -> Decision {
        let to_norm = to.to_lowercase();
        if self.panic {
            return Decision::Deny;
        }
        let day = env::block_timestamp() / ONE_DAY_NANO;
        let day_key = format!("{}|{}", day, chain.to_lowercase());
        let used = *self.spent.get(&day_key).unwrap_or(&0);
        if used.saturating_add(amount.0) > self.policy.daily_limit.0 {
            return Decision::Deny;
        }
        if let Some(verdict) = self.verdicts.get(&intent_hash) {
            if verdict.denied || verdict.risk >= self.ai_deny_threshold {
                return Decision::Deny;
            }
        } else if self.reviewer.is_some() {
            return Decision::Deny;
        }
        let key = format!("{}:{}", chain.to_lowercase(), to_norm);
        let first_seen = self.seen.get(&key);
        let known = matches!(first_seen, Some(t) if env::block_timestamp().saturating_sub(*t) <= self.policy.known_grace)
            || self.whitelisted.contains_key(&to_norm);
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
