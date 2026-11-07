# Changelog — Aegis audit fixes (2026-11-07)

Audit: `AEGIS_AUDIT.md` (F1–F18). All contract fixes deployed to a **new**
contract account (`watchdog-v3-4d8a7f.testnet`); v1/v2 left untouched.
State is borsh/layout-bound, so no in-place upgrade was attempted.

## Phase A (no redeploy)

| Finding | Commit | What changed |
|---|---|---|
| F5 + F12 | `f860896` | Signer always calls `evaluate_tx` (records spend), signs only on `Approve`, then `confirm_broadcast`; real nonce + estimated gas/fees |
| F7 | `3df7432` | Verdict parsing fails closed (integer risk 0-100, real boolean, no coercion; risk=100 fallback after retries) |
| F13 + F11-part | `3325a30` | Dashboard derives operator from `get_operator()` and ETH address via chainsig; deploy funds via Transfer action, default ≥ 3 NEAR |
| F17/F18 | `b3d1b6b` | Docs synced (29 tests, wasm name), `overflow-checks = true`, non-payable `cancel_hold`, env quote stripping, API model recorded |
| F11 (setup.sh) | `f1d1279` | `setup.sh` uses valid near-cli-rs sub-commands (`sponsor-by-faucet-service`), threshold as a parameter |

## Phase B (contract changes → v3 redeploy)

| Finding | Commit | What changed | Redeploy |
|---|---|---|---|
| F16 | `e283d65` | `set_quiet_period` renamed to `set_quiet_period_ns` |
| F8/F9 | `73f21f1` | Per-chain daily limits (default 0.01 ETH, comment fixed), per-chain whitelist, `remove_employee` cleans whitelist/seen |
| F1 (Critical) | `718f901` | `seen` no longer written on hold open; `release_hold` added; open hold keeps `evaluate_tx` at Hold (double-evaluate regression test) |
| F3 | `a5d81f2` | Verdict key computed on-chain from `(chain,to,amount,memo_hash,nonce)`; verdicts single-use + TTL (10 min); tooling updated |
| F4 | `3e25c30` | Admin timelock (`propose_*` → `apply_*` after 1-day delay, guardian veto); minimum 5 min panic cooldown; limit increases timelocked |
| F6/F10 | `9a2ce81` | Released holds/capsules feed `evaluate_tx` as pre-approved entries; heirs split NEAR accounts + ETH addresses, M-of-N claim, chain-scoped whitelist |
| F15 | `3efffdb` | `std HashMap` → `near_sdk::store::{LookupMap, IterableMap}` |
| F2 | `a5d81f2`* | Documentation-only (default per audit): README trust model states the policy governs the cooperating signer; stolen operator key can call MPC directly |

## Verification

- `cargo test`: **29/29 pass** (incl. inverted PoC regression tests for F1/F3/F4/F6/F10)
- Benchmark re-run against v3: **18/18 pass** (11 attacks, 4 controls, 2 stateful, 1 panic cycle)
- `npm run build` green for frontend
- v3 contract: `watchdog-v3-4d8a7f.testnet` (operator, reviewer, 2 guardians, whitelist configured)
