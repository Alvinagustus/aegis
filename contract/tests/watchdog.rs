use near_sdk::json_types::U128;
use near_sdk::test_utils::{accounts, VMContextBuilder};
use near_sdk::{testing_env, AccountId, NearToken};
use watchdog::{Decision, HoldStatus, Watchdog};

const OPERATOR: &str = "wallet.testnet";
const GUARD1: &str = "guard1.testnet";
const GUARD2: &str = "guard2.testnet";
const DAY: u64 = 86_400_000_000_000;

fn expect_panic<F: FnOnce()>(f: F) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    assert!(result.is_err(), "expected a panic but none occurred");
}

fn oper() -> AccountId {
    OPERATOR.parse().unwrap()
}

fn contract() -> Watchdog {
    Watchdog::new(oper(), 2)
}

fn as_operator(ctx: &mut VMContextBuilder) {
    testing_env!(ctx
        .predecessor_account_id(oper())
        .signer_account_id(oper())
        .attached_deposit(NearToken::from_yoctonear(1))
        .build());
}

fn addr(ctx: &mut VMContextBuilder) {
    testing_env!(ctx.predecessor_account_id(oper()).build());
}

#[test]
fn first_seen_address_is_held() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    testing_env!(ctx.predecessor_account_id(oper()).build());
    assert_eq!(c.evaluate_tx("eth".into(), "0xdeadbeef".into(), U128(100), "".into(), 0), Decision::Hold);
    let h = c.get_hold(1).unwrap();
    assert_eq!(h.status, HoldStatus::Pending);
    assert_eq!(h.to, "0xdeadbeef");
}

#[test]
fn whitelist_is_approved_and_spends_limit() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    as_operator(&mut ctx);
    c.whitelist_add("eth".into(), "0xcold".into());
    assert_eq!(c.evaluate_tx("eth".into(), "0xCOLD".into(), U128(10), "memo".into(), 0), Decision::Approve);
    assert_eq!(c.evaluate_tx("eth".into(), "0xcold".into(), U128(10), "memo".into(), 0), Decision::Approve);
    c.set_daily_limit("eth".into(), U128(20));
    assert_eq!(c.evaluate_tx("eth".into(), "0xcold".into(), U128(10), "memo".into(), 0), Decision::Deny);
}

#[test]
fn non_operator_cannot_evaluate() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    testing_env!(ctx.predecessor_account_id(accounts(1)).build());
    expect_panic(|| {
        c.evaluate_tx("eth".into(), "0xdeadbeef".into(), U128(100), "".into(), 0);
    });
}

#[test]
fn guardian_escalation_clears_hold() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.evaluate_tx("eth".into(), "0xunknown".into(), U128(100), "".into(), 0);
    c.guardian_add(GUARD1.parse().unwrap());
    c.guardian_add(GUARD2.parse().unwrap());

    testing_env!(ctx.predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.hold_escalate(1);
    assert_eq!(c.get_hold(1).unwrap().status, HoldStatus::Pending);

    testing_env!(ctx.predecessor_account_id(GUARD2.parse().unwrap()).build());
    c.hold_escalate(1);
    let h = c.get_hold(1).unwrap();
    match h.status {
        HoldStatus::Cleared { release_at } => {
            assert!(release_at > h.requested_at);
        }
        other => panic!("expected cleared, got {:?}", other),
    }
}

#[test]
fn owner_can_cancel_pending_and_cleared_hold() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.evaluate_tx("eth".into(), "0xunknown".into(), U128(100), "".into(), 0);
    c.guardian_add(GUARD1.parse().unwrap());

    testing_env!(ctx.predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.hold_escalate(1);

    as_operator(&mut ctx);
    testing_env!(ctx
        .predecessor_account_id(oper())
        .signer_account_id(oper())
        .attached_deposit(NearToken::from_yoctonear(0))
        .build());
    c.cancel_hold(1);
    assert_eq!(c.get_hold(1).unwrap().status, HoldStatus::Cancelled);
}

#[test]
fn strays_cannot_cancel_hold() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.evaluate_tx("eth".into(), "0xunknown".into(), U128(100), "".into(), 0);
    testing_env!(ctx.predecessor_account_id(accounts(3)).build());
    expect_panic(|| c.cancel_hold(1));
}

#[test]
fn guardian_panic_freezes_then_owner_unfreezes_after_cooldown() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.guardian_add(GUARD1.parse().unwrap());

    testing_env!(ctx.predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.panic_on();
    assert!(c.is_panicked());
    assert_eq!(c.simulate_tx("eth".into(), "0xcold".into(), U128(1), "".into(), 0), Decision::Deny);

    // owner cannot unfreeze immediately
    as_operator(&mut ctx);
    expect_panic(|| c.panic_off());

    // nor after 2 days...
    testing_env!(ctx.block_timestamp(2 * DAY).build());
    expect_panic(|| c.panic_off());
    assert!(c.is_panicked());

    // ...but after 3 days, yes
    testing_env!(ctx.block_timestamp(3 * DAY).build());
    c.panic_off();
    assert!(!c.is_panicked());
}

#[test]
fn only_guardians_can_panic() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    testing_env!(ctx.predecessor_account_id("stray.testnet".parse().unwrap()).build());
    expect_panic(|| c.panic_on());
}

#[test]
fn owner_can_unfreeze_and_owner_only() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.guardian_add(GUARD1.parse().unwrap());
    c.whitelist_add("eth".into(), "0xcold".into());

    // guardian should not be able to whitelist (their use is only escalation/panic)
    testing_env!(ctx.predecessor_account_id(GUARD1.parse().unwrap()).build());
    expect_panic(|| c.whitelist_add("eth".into(), "0xevil".into()));
    assert!(!c.is_whitelisted("eth".into(), "0xevil".into()));
}

const REVIEWER: &str = "ai-reviewer.testnet";

fn with_reviewer(c: &mut Watchdog, ctx: &mut VMContextBuilder) {
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    c.set_reviewer(Some(REVIEWER.parse().unwrap()));
}

// ------------------------------------------------------------------
// AI review governance
// ------------------------------------------------------------------

/// Reviewer configured + verdict missing for the intent -> denied.
#[test]
fn no_verdict_means_no_transfer() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);
    as_operator(&mut ctx);
    c.whitelist_add("eth".into(), "0xcold".into());
    // even a whitelisted address is blocked until the reviewer signs off
    assert_eq!(
        c.evaluate_tx("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 0),
        Decision::Deny
    );
}

/// Reviewer's explicit deny beats the whitelist and the daily limit ordering.
#[test]
fn ai_deny_overrides_whitelist() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);
    as_operator(&mut ctx);
    c.whitelist_add("eth".into(), "0xcold".into());

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    let key = c.compute_intent_hash("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 0);
    c.submit_verdict(key, 99, true, "watchdog-risk-v1".into());

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    assert_eq!(
        c.evaluate_tx("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 0),
        Decision::Deny
    );
}

/// Low-risk verdict + whitelisted address -> smooth approve.
#[test]
fn ai_clears_transfers() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);
    as_operator(&mut ctx);
    c.whitelist_add("eth".into(), "0xcold".into());

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    let key = c.compute_intent_hash("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 0);
    c.submit_verdict(key.clone(), 5, false, "watchdog-risk-v1".into());
    let v = c.get_ai_verdict(key.clone()).unwrap();
    assert_eq!(v.risk, 5);
    assert_eq!(v.model, "watchdog-risk-v1");

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    assert_eq!(
        c.evaluate_tx("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 0),
        Decision::Approve
    );
    // single-use: verdict consumed by the approve
    assert!(c.get_ai_verdict(key).is_none());
}

/// High risk (>= threshold) denies even without an explicit `denied` flag.
#[test]
fn high_risk_score_blocks_transfer() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);
    as_operator(&mut ctx);
    c.whitelist_add("eth".into(), "0xcold".into());
    c.set_ai_deny_threshold(70);

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    let key = c.compute_intent_hash("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 0);
    c.submit_verdict(key, 70, false, "watchdog-risk-v1".into());
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    assert_eq!(
        c.evaluate_tx("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 0),
        Decision::Deny
    );

    // just below the threshold sails through
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    let key2 = c.compute_intent_hash("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 1);
    c.submit_verdict(key2, 69, false, "watchdog-risk-v1".into());
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    assert_eq!(
        c.evaluate_tx("eth".into(), "0xcold".into(), U128(5), "memo-b".into(), 1),
        Decision::Approve
    );
}

/// Only the appointed reviewer can submit verdicts — the operator cannot
/// forge a "safe" score for its own transfer.
#[test]
fn only_reviewer_submits_verdicts() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);

    as_operator(&mut ctx);
    expect_panic(|| c.submit_verdict("intent-b".into(), 0, false, "forged".into()));

    testing_env!(ctx.block_timestamp(0).predecessor_account_id("stray.testnet".parse().unwrap()).build());
    expect_panic(|| c.submit_verdict("intent-b".into(), 0, false, "forged".into()));

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    c.submit_verdict("intent-b".into(), 0, false, "watchdog-risk-v1".into());
    assert!(c.get_ai_verdict("intent-b".into()).is_some());
}

/// With a short configured cooldown, the full panic cycle completes fast —
// ------------------------------------------------------------------
// Time capsule / inheritance / payroll
// ------------------------------------------------------------------

/// Capsule cannot be released before its date, can after, and the
/// owner can cancel before release like any hold.
#[test]
fn capsule_seal_release_and_cancel() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    let id = c.create_capsule("eth".into(), "0xheir".into(), U128(100), 2 * DAY, "for your 18th".into());
    let h = c.get_hold(id).unwrap();
    assert_eq!(h.message, "for your 18th");
    assert_eq!(h.capsule_release_at, 2 * DAY);

    // too early
    testing_env!(ctx.block_timestamp(DAY).build());
    expect_panic(|| c.release_capsule(id));

    // after date: permissionless release
    testing_env!(ctx.block_timestamp(2 * DAY).build());
    c.release_capsule(id);
    assert_eq!(c.get_hold(id).unwrap().status, HoldStatus::Released);

    // second capsule cancelled by owner before release
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    let id2 = c.create_capsule("eth".into(), "0xheir".into(), U128(10), 5 * DAY, "".into());
    testing_env!(ctx
        .block_timestamp(DAY)
        .predecessor_account_id(oper())
        .attached_deposit(NearToken::from_yoctonear(1))
        .build());
    c.cancel_hold(id2);
    assert_eq!(c.get_hold(id2).unwrap().status, HoldStatus::Cancelled);

    // past/present release date rejected
    testing_env!(ctx.block_timestamp(10 * DAY).predecessor_account_id(oper()).build());
    expect_panic(|| { c.create_capsule("eth".into(), "0xheir".into(), U128(1), 10 * DAY, "".into()); });
}

/// Inheritance: check-in resets the clock; after silence a guardian
/// opens it; heirs become whitelisted; nobody else can.
#[test]
fn inheritance_checkin_timeout_and_claim() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.set_heirs(vec!["heir1.testnet".into(), "heir2.testnet".into()]);
    c.set_inheritance_timeout(DAY);
    c.guardian_add(GUARD1.parse().unwrap());

    // owner still active -> guardian cannot claim
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(GUARD1.parse().unwrap()).build());
    expect_panic(|| c.claim_inheritance());

    // check-in at t=1d resets clock; claim at t=1.5d still too early
    testing_env!(ctx.block_timestamp(DAY).predecessor_account_id(oper()).build());
    c.check_in();
    testing_env!(ctx.block_timestamp(DAY + DAY / 2).predecessor_account_id(GUARD1.parse().unwrap()).build());
    expect_panic(|| c.claim_inheritance());

    // stranger cannot claim even after timeout
    testing_env!(ctx.block_timestamp(3 * DAY).predecessor_account_id("stray.testnet".parse().unwrap()).build());
    expect_panic(|| c.claim_inheritance());

    // guardian claims after silence
    testing_env!(ctx.block_timestamp(3 * DAY).predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.claim_inheritance();
    assert!(c.is_inheritance_open());
    assert!(c.is_whitelisted("eth".into(), "heir1.testnet".into()));
}

/// Payroll: registered employees are paid in one batch under the
/// daily limit; an oversized batch is rejected whole.
#[test]
fn payroll_batch_under_limit() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.add_employee("0xa1".into(), U128(100));
    c.add_employee("0xb2".into(), U128(200));
    c.set_daily_limit("eth".into(), U128(1000));
    assert_eq!(c.run_payroll("eth".into()), 2);
    assert_eq!(c.get_payroll_runs(), 1);
    assert!(c.is_whitelisted("eth".into(), "0xa1".into()));

    // oversized batch rejected whole
    c.add_employee("0xc3".into(), U128(900));
    expect_panic(|| { c.run_payroll("eth".into()); });

    // only operator runs payroll
    testing_env!(ctx.predecessor_account_id(GUARD1.parse().unwrap()).build());
    // (guardian not registered here, but must fail regardless)
    expect_panic(|| { c.run_payroll("eth".into()); });
}
/// this is the testnet/test-contract path; production keeps 3 days.
#[test]
fn short_cooldown_panic_cycle() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.guardian_add(GUARD1.parse().unwrap());
    c.propose_panic_cooldown(300_000_000_000); // 5 min (the minimum)
    testing_env!(ctx.block_timestamp(2 * DAY).build());
    c.apply_panic_cooldown();

    testing_env!(ctx.block_timestamp(2 * DAY).predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.panic_on();
    assert!(c.is_panicked());

    // still cooling down at t=2d+100s
    testing_env!(ctx.block_timestamp(2 * DAY + 100_000_000_000).predecessor_account_id(oper()).build());
    expect_panic(|| c.panic_off());
    assert!(c.is_panicked());

    // unlocked at t=2d+301s
    testing_env!(ctx.block_timestamp(2 * DAY + 301_000_000_000).predecessor_account_id(oper()).build());
    c.panic_off();
    assert!(!c.is_panicked());
}

/// Guardians cannot escalate a capsule — it releases with time only,
/// otherwise the capsule record would be stuck in Cleared forever.
#[test]
fn capsule_rejects_escalation_and_panic_release() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.guardian_add(GUARD1.parse().unwrap());
    let id = c.create_capsule("eth".into(), "0xheir".into(), U128(100), 2 * DAY, "".into());
    testing_env!(ctx.block_timestamp(DAY).predecessor_account_id(GUARD1.parse().unwrap()).build());
    expect_panic(|| c.hold_escalate(id));

    // panic blocks capsule release even after the date
    testing_env!(ctx.block_timestamp(DAY).predecessor_account_id(oper()).build());
    c.propose_panic_cooldown(300_000_000_000);
    testing_env!(ctx.block_timestamp(2 * DAY).predecessor_account_id(oper()).build());
    c.apply_panic_cooldown();
    testing_env!(ctx.block_timestamp(2 * DAY).predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.panic_on();
    testing_env!(ctx.block_timestamp(3 * DAY).build());
    expect_panic(|| c.release_capsule(id));
}

/// Owner returning after inheritance was opened closes it and
/// un-whitelists the heirs.
#[test]
fn inheritance_closes_on_checkin() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.set_heirs(vec!["heir1.testnet".into()]);
    c.set_inheritance_timeout(DAY);
    c.guardian_add(GUARD1.parse().unwrap());

    testing_env!(ctx.block_timestamp(3 * DAY).predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.claim_inheritance();
    assert!(c.is_whitelisted("eth".into(), "heir1.testnet".into()));

    // owner comes back: check-in closes it
    testing_env!(ctx.block_timestamp(4 * DAY).predecessor_account_id(oper()).build());
    c.check_in();
    assert!(!c.is_inheritance_open());
    assert!(!c.is_whitelisted("eth".into(), "heir1.testnet".into()));
}

/// Only the operator may propose admin changes.
#[test]
fn only_operator_sets_cooldown() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.guardian_add(GUARD1.parse().unwrap());
    testing_env!(ctx.predecessor_account_id(GUARD1.parse().unwrap()).build());
    expect_panic(|| c.propose_panic_cooldown(DAY));
}

/// F1 regression (audit poc_f1, inverted): calling evaluate_tx twice to a
/// new address must stay Hold both times — the quiet period is no longer
/// bypassed. Release only marks the address seen after eligibility.
#[test]
fn f1_double_evaluate_stays_held() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    // first call opens the hold (whitelist so AI/limit rules don't interfere)
    c.whitelist_add("eth".into(), "0xattacker".into());
    // without reviewer and whitelist "known" via grace after release only:
    // use an unknown address instead:
    c.whitelist_remove("eth".into(), "0xattacker".into());
    let d1 = c.evaluate_tx("eth".into(), "0xattacker".into(), U128(100), "h".into(), 0);
    let d2 = c.evaluate_tx("eth".into(), "0xattacker".into(), U128(100), "h".into(), 0);
    assert_eq!(d1, Decision::Hold);
    assert_eq!(d2, Decision::Hold); // was Approve before the F1 fix

    // release the hold after the quiet period, then evaluate approves
    c.set_quiet_period_ns(DAY);
    testing_env!(ctx.block_timestamp(2 * DAY).build());
    c.release_hold(1);
    assert_eq!(c.get_hold(1).unwrap().status, HoldStatus::Released);
    let d3 = c.evaluate_tx("eth".into(), "0xattacker".into(), U128(100), "h".into(), 0);
    assert_eq!(d3, Decision::Approve);
}

/// F3 regression (audit poc_f2, inverted): a verdict bound to one transfer
/// cannot be reused for a different amount — the lookup key is computed
/// on-chain, so a benign hash for 0.001 ETH approves nothing else.
#[test]
fn f3_verdict_bound_to_transfer() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);
    as_operator(&mut ctx);
    c.whitelist_add("eth".into(), "0xcold".into());

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    // benign verdict for a tiny transfer
    let key = c.compute_intent_hash("eth".into(), "0xcold".into(), U128(1_000_000), "m".into(), 0);
    c.submit_verdict(key, 1, false, "m".into());

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    // same memo/amount ok, but a 1000x amount with the same memo_hash+nonce
    // must not find that verdict
    let d = c.evaluate_tx("eth".into(), "0xcold".into(), U128(1_000_000_000_000), "m".into(), 0);
    assert_eq!(d, Decision::Deny);
}

/// Verdicts expire after the TTL: a stale low-risk verdict is treated as absent.
#[test]
fn f3_verdict_expires() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);
    as_operator(&mut ctx);
    c.whitelist_add("eth".into(), "0xcold".into());

    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    let key = c.compute_intent_hash("eth".into(), "0xcold".into(), U128(5), "m".into(), 0);
    c.submit_verdict(key, 1, false, "m".into());

    testing_env!(ctx.block_timestamp(20 * 60_000_000_000).predecessor_account_id(oper()).build());
    let d = c.evaluate_tx("eth".into(), "0xcold".into(), U128(5), "m".into(), 0);
    assert_eq!(d, Decision::Deny); // expired (TTL = 10 min)
}

/// F4 regression (audit poc_f3, inverted): owner cannot zero the panic
/// cooldown — below-minimum proposals are rejected and changes are
/// timelocked, so a stolen owner key cannot instantly dismiss a guardian.
#[test]
fn f4_panic_cooldown_timelocked_and_minimum() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    c.guardian_add(GUARD1.parse().unwrap());

    // below minimum (5m): cannot even propose
    expect_panic(|| c.propose_panic_cooldown(0));

    // proposals cannot be applied before admin_delay (1 day)
    c.propose_panic_cooldown(DAY);
    expect_panic(|| c.apply_panic_cooldown());

    // guardian veto kills the change
    c.guardian_add(GUARD1.parse().unwrap());
    testing_env!(ctx.block_timestamp(3600_000_000_000).predecessor_account_id(GUARD1.parse().unwrap()).build());
    c.guardian_veto("panic_cooldown".into());
    testing_env!(ctx.block_timestamp(2 * DAY).predecessor_account_id(oper()).build());
    expect_panic(|| c.apply_panic_cooldown());

    // after the delay, without veto, it applies
    c.propose_panic_cooldown(DAY);
    testing_env!(ctx.block_timestamp(4 * DAY).predecessor_account_id(oper()).build());
    c.apply_panic_cooldown();
    assert_eq!(c.get_policy().panic_cooldown, DAY);
}

/// F4: daily limit increases are timelocked; decreases are direct.
#[test]
fn f4_limit_increase_timelocked() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    addr(&mut ctx);
    // direct increase rejected
    expect_panic(|| c.set_daily_limit("eth".into(), U128(u128::MAX)));
    // decrease is direct
    c.set_daily_limit("eth".into(), U128(10));
    assert_eq!(c.get_policy().limit_for("eth"), 10);
    // increase via propose + apply after delay
    c.propose_daily_limit("eth".into(), U128(100));
    expect_panic(|| c.apply_daily_limit("eth".into()));
    testing_env!(ctx.block_timestamp(2 * DAY).build());
    c.apply_daily_limit("eth".into());
    assert_eq!(c.get_policy().limit_for("eth"), 100);
}

/// Risk out of range is rejected.
#[test]
fn verdict_validates_inputs() {
    let mut c = contract();
    let mut ctx = VMContextBuilder::new();
    with_reviewer(&mut c, &mut ctx);
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(REVIEWER.parse().unwrap()).build());
    expect_panic(|| c.submit_verdict("intent-b".into(), 101, false, "m".into()));
    expect_panic(|| c.submit_verdict("tiny".into(), 1, false, "m".into()));
    // operator cannot appoint itself and then self-approve... it *can*,
    // but it is on-chain visible — disclosed limitation; reviewer *removal*
    // is timelocked (F4), so check the propose/apply path instead
    testing_env!(ctx.block_timestamp(0).predecessor_account_id(oper()).build());
    c.propose_reviewer_none();
    testing_env!(ctx.block_timestamp(2 * DAY).predecessor_account_id(oper()).build());
    c.apply_reviewer_none();
    assert!(c.get_reviewer().is_none());
}
