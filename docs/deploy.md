# Deploying to NEAR testnet

## Accounts (suffix: 4d8a7f)

| Role | Account | Purpose |
|---|---|---|
| Deployer / operator | `watchdog-wallet-4d8a7f.testnet` | Calls `evaluate_tx`; deploys contract |
| Contract v1 (policy engine) | `watchdog-policy-4d8a7f.testnet` | Policy engine (watchdog.wasm) |
| Contract v2 (capsule / inheritance / payroll) | `watchdog-v2-4d8a7f.testnet` | Same engine + 3 usage patterns |
| Test contract (panic flow, 60 s cooldown) | `watchdog-test-4d8a7f.testnet` | Panic-cycle testing only |
| AI reviewer | `watchdog-reviewer-4d8a7f.testnet` | Submits `submit_verdict` |
| Guardian | `watchdog-guardian-4d8a7f.testnet` | `panic_on` / `hold_escalate` |
| Guardian #2 | `watchdog-guardian2-4d8a7f.testnet` | 2nd `hold_escalate` vote (threshold = 2) |

Keys stay in the near-cli keychain (`~/.config/near-cli`); do not copy them
into this repo. The reviewer script reads its key from `.env` instead.

## Commands (near-cli-rs)

```sh
# 1. create funded testnet accounts (NEAR faucet)
near create-account watchdog-wallet-4d8a7f.testnet --useFaucet --networkId testnet
near create-account watchdog-policy-4d8a7f.testnet  --useFaucet --networkId testnet
near create-account watchdog-reviewer-4d8a7f.testnet --useFaucet --networkId testnet
near create-account watchdog-guardian-4d8a7f.testnet  --useFaucet --networkId testnet

# 2. deploy contract code
near deploy watchdog-policy-4d8a7f.testnet \
  contract/target/wasm32-unknown-unknown/release/watchdog.wasm \
  --networkId testnet

# 3. initialise (operator = the wallet account, threshold = 2 guardians)
near call watchdog-policy-4d8a7f.testnet new \
  '{"operator":"watchdog-wallet-4d8a7f.testnet","guard_threshold":2}' \
  --useAccount watchdog-wallet-4d8a7f.testnet --networkId testnet

# 4. smoke test BEFORE appointing a reviewer: unknown address -> Hold
near call watchdog-policy-4d8a7f.testnet evaluate_tx \
  '{"chain":"eth","to":"0x0000000000000000000000000000000000000000","amount":"1000","intent_hash":""}' \
  --useAccount watchdog-wallet-4d8a7f.testnet --networkId testnet

# 5. appoint reviewer + guardian (from now on, transfers need a verdict)
near call watchdog-policy-4d8a7f.testnet set_reviewer \
  '{"reviewer":"watchdog-reviewer-4d8a7f.testnet"}' \
  --useAccount watchdog-wallet-4d8a7f.testnet --networkId testnet
near call watchdog-policy-4d8a7f.testnet guardian_add \
  '{"account":"watchdog-guardian-4d8a7f.testnet"}' \
  --useAccount watchdog-wallet-4d8a7f.testnet --networkId testnet
```
