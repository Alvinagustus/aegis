# Deploying to NEAR testnet

## Accounts (suffix: 4d8a7f)

| Role | Account | Purpose |
|---|---|---|
| Deployer / operator | `watchdog-wallet-4d8a7f.testnet` | Calls `evaluate_tx`; deploys contract |
| Contract v1 | `watchdog-policy-4d8a7f.testnet` | First policy engine |
| Contract v2 | `watchdog-v2-4d8a7f.testnet` | Capsule / inheritance / payroll |
| Contract v3 | `watchdog-v3-4d8a7f.testnet` | Audit fixes + first universal timelock |
| Contract v4 | `watchdog-v4-4d8a7f.testnet` | Re-audit fixes (demo, legacy delay 0) |
| Contract (current) | `aegispolicy.testnet` | V1–V8 + H6 fixes, 1-day timelock, `new_configured` |
| Test contract (legacy panic cycle) | `watchdog-test-4d8a7f.testnet` | Panic-cycle testing only |
| AI reviewer | `watchdog-reviewer-4d8a7f.testnet` | Submits `submit_verdict` |
| Guardian | `watchdog-guardian-4d8a7f.testnet` | `panic_on` / `hold_escalate` |
| Guardian #2 | `watchdog-guardian2-4d8a7f.testnet` | 2nd `hold_escalate` vote (threshold = 2) |

Keys stay in the near-cli keychain (`~/.config/near-cli`); do not copy them
into this repo. The reviewer script reads its key from `.env` instead.

## Commands (near-cli-rs)

```sh
# 1. create a funded testnet account (NEAR faucet)
near account create-account sponsor-by-faucet-service aegispolicy.testnet \
  autogenerate-new-keypair save-to-keychain network-config testnet create

# 2. build + deploy (no init call yet)
(cd contract && cargo build --target wasm32-unknown-unknown --release)
near contract deploy aegispolicy.testnet \
  use-file contract/target/wasm32-unknown-unknown/release/watchdog.wasm \
  without-init-call network-config testnet sign-with-keychain send

# 3. initialise atomically: operator, threshold, 1-day delay, reviewer,
#    guardians and whitelist all in one call (V1 — no post-init setters)
near contract call-function as-transaction aegispolicy.testnet new_configured \
  json-args '{
    "operator":"watchdog-wallet-4d8a7f.testnet",
    "guard_threshold":2,
    "admin_delay":86400000000000,
    "reviewer":"watchdog-reviewer-4d8a7f.testnet",
    "guardians":["watchdog-guardian-4d8a7f.testnet","watchdog-guardian2-4d8a7f.testnet"],
    "whitelist":[["eth","0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]]
  }' \
  prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
  sign-as aegispolicy.testnet network-config testnet sign-with-keychain send

# 4. verify
near contract call-function as-read-only aegispolicy.testnet get_admin_delay \
  json-args '{}' network-config testnet now
near contract call-function as-read-only aegispolicy.testnet get_policy \
  json-args '{}' network-config testnet now
```

## Changing the configuration after deploy

Every sensitive setter is `propose_*` → `apply_*` (V1):

```sh
# propose now (guardians can veto during the timelock)
near contract call-function as-transaction aegispolicy.testnet propose_reviewer \
  json-args '{"reviewer":"new-reviewer.testnet"}' \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  sign-as watchdog-wallet-4d8a7f.testnet network-config testnet sign-with-keychain send

# apply after admin_delay has elapsed
near contract call-function as-transaction aegispolicy.testnet apply_reviewer \
  json-args '{}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  sign-as watchdog-wallet-4d8a7f.testnet network-config testnet sign-with-keychain send
```

The delay can only be increased instantly; lowering it is itself
`propose_admin_delay` + `apply_admin_delay`, floored at 5 minutes. Guardians
read the payload with `get_admin_payload` / `get_admin_proposals` and call
`guardian_veto(action)` to cancel a malicious proposal.
