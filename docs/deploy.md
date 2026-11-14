# Deploying Aegis to NEAR testnet

## Accounts

| Role | Account | Purpose |
|---|---|---|
| Contract | `aegis.testnet` | Policy engine + contract-bound MPC signing (XCC) |
| Operator | `aegis-operator.testnet` | Calls `evaluate_tx` / `evaluate_and_sign`; deploys/operates |
| AI reviewer | `aegis-reviewer.testnet` | Submits `submit_verdict` |
| Guardian | `aegis-guardian.testnet` | `panic_on` / `hold_escalate` |
| Guardian #2 | `aegis-guardian2.testnet` | 2nd `hold_escalate` vote (threshold = 2) |

Keys stay in the local near-cli/keychain or `.env` (gitignored) — never in the repo.

## Build, deploy, initialize (contract-bound MPC)

```sh
# 1. create a funded testnet account (NEAR faucet)
near account create-account sponsor-by-faucet-service aegis.testnet \
  autogenerate-new-keypair save-to-keychain network-config testnet create

# 2. build + deploy (no init call yet)
(cd contract && cargo build --target wasm32-unknown-unknown --release)
near contract deploy aegis.testnet \
  use-file contract/target/wasm32-unknown-unknown/release/aegis.wasm \
  without-init-call network-config testnet sign-with-keychain send

# 3. initialize atomically (includes mpc_contract; defaults to v1.signer-prod.testnet when null)
near contract call-function as-transaction aegis.testnet new_configured \
  json-args '{
    "operator":"aegis-operator.testnet",
    "guard_threshold":2,
    "admin_delay":86400000000000,
    "reviewer":"aegis-reviewer.testnet",
    "guardians":["aegis-guardian.testnet","aegis-guardian2.testnet"],
    "whitelist":[["eth","0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]],
    "mpc_contract":"v1.signer-prod.testnet"
  }' \
  prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
  sign-as aegis.testnet network-config testnet sign-with-keychain send

# 4. verify
near contract call-function as-read-only aegis.testnet get_operator json-args '{}' network-config testnet now
near contract call-function as-read-only aegis.testnet get_mpc_contract json-args '{}' network-config testnet now
near contract call-function as-read-only aegis.testnet get_policy json-args '{}' network-config testnet now
```

> Note: contract state is borsh-serialized and layout-bound. Deploy major changes to a fresh account (no in-place state-layout migration).

## Contract-bound signing (NEAR → Ethereum Sepolia)

`evaluate_and_sign` enforces policy, binds unsigned EIP-1559 `to`/`value` from RLP to the intent, and on `Approve` performs an XCC to `v1.signer-prod.testnet::sign` (`on_sign_callback` refunds `daily_spent` on failure). The controlled EVM address is derived from the **contract account** (path `ethereum-1`).

1. Derive and fund the contract-bound ETH address with Sepolia ETH.
2. Submit an AI verdict for the intent (`tools/reviewer`).
3. Run the untrusted relayer:
   ```sh
   cd tools/chainsig && npm install
   AEGIS_CONTRACT=aegis.testnet CALLER_ACCOUNT=aegis-operator.testnet \
     node sign-eth.mjs <to> <amount_eth> [memo]
   # → unsigned tx → evaluate_and_sign (policy + RLP binding + MPC XCC) → signature + broadcast
   ```

## Admin changes (timelocked)

Every sensitive setter is `propose_*` → `apply_*` (1-day delay by default, floored at 5 minutes, capped at 30 days). Guardians can `guardian_veto(action)` during the timelock.

```sh
near contract call-function as-transaction aegis.testnet propose_reviewer \
  json-args '{"reviewer":"<new-reviewer.testnet>"}' \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  sign-as aegis-operator.testnet network-config testnet sign-with-keychain send

# after admin_delay
near contract call-function as-transaction aegis.testnet apply_reviewer \
  json-args '{}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
  sign-as aegis-operator.testnet network-config testnet sign-with-keychain send
```
