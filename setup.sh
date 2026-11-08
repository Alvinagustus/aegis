#!/usr/bin/env bash
# Aegis — one-command setup for casual users.
#
# Deploys the Aegis policy contract to a fresh account, initializes it with
# YOU as operator, and configures reviewer + guardian. Daily use after this
# is 100% from the dashboard (browser wallet).
#
# Usage:
#   ./setup.sh <your-near-account> <contract-account> [reviewer] [guardian] [threshold]
# Examples:
#   ./setup.sh suisei.testnet aegis.svisei.testnet \
#     watchdog-reviewer-4d8a7f.testnet watchdog-guardian-4d8a7f.testnet 2
#
# Prerequisites: near-cli-rs on PATH, Rust-built watchdog.wasm, and your
# account funded on testnet (faucet: https://near-faucet.io).

set -euo pipefail

OPERATOR="${1:-}"
CONTRACT="${2:-}"
REVIEWER="${3:-}"
GUARDIAN="${4:-}"
THRESHOLD="${5:-1}"
NETWORK="testnet"

if [[ -z "$OPERATOR" || -z "$CONTRACT" ]]; then
  echo "usage: ./setup.sh <your-near-account> <contract-account> [reviewer] [guardian] [threshold]"
  exit 1
fi

WASM="contract/target/wasm32-unknown-unknown/release/watchdog.wasm"
if [[ ! -f "$WASM" ]]; then
  echo "watchdog.wasm not found at $WASM"
  echo "build it:  (cd contract && cargo build --target wasm32-unknown-unknown --release)"
  exit 1
fi

# 1. create contract account (testnet faucet sponsors it; mainnet users must
#    fund an existing account instead — sponsor-by-faucet is testnet-only)
echo "→ creating $CONTRACT (sponsored by testnet faucet)"
near account create-account sponsor-by-faucet-service "$CONTRACT" \
  autogenerate-new-keypair save-to-keychain network-config "$NETWORK" create

# 2. deploy code
echo "→ deploying contract code"
near contract deploy "$CONTRACT" use-file "$WASM" without-init-call \
  network-config "$NETWORK" sign-with-keychain send

# 3. initialise with you as operator (config is atomic at init: V1)
echo "→ initializing (operator = $OPERATOR, threshold = $THRESHOLD)"
INIT_ARGS="{\"operator\":\"$OPERATOR\",\"guard_threshold\":$THRESHOLD"
if [[ -n "$GUARDIAN" ]]; then
  if [[ "$THRESHOLD" -gt 1 ]]; then
    echo "this script accepts one guardian; use threshold 1 and add the rest via propose/apply"
    exit 1
  fi
  if [[ -n "$REVIEWER" ]]; then REVIEWER_JSON="\"$REVIEWER\""; else REVIEWER_JSON=null; fi
  INIT_METHOD="new_configured"
  INIT_ARGS="$INIT_ARGS,\"admin_delay\":86400000000000,\"reviewer\":$REVIEWER_JSON,\"guardians\":[\"$GUARDIAN\"],\"whitelist\":[]}"
else
  if [[ -n "$REVIEWER" ]]; then
    echo "a reviewer needs a guardian at init (threshold >= 1): pass a guardian too"
    exit 1
  fi
  INIT_METHOD="new"
  INIT_ARGS="$INIT_ARGS}"
fi
near contract call-function as-transaction "$CONTRACT" "$INIT_METHOD" \
  json-args "$INIT_ARGS" \
  prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$OPERATOR" network-config "$NETWORK" sign-with-keychain send

echo "✅ Aegis is live at $CONTRACT (operator: $OPERATOR)"
echo "   Admin changes are timelocked 1 day: propose_* → apply_* (guardians can veto)."
echo "   Next: open the dashboard, connect your wallet, switch to:"
echo "   $CONTRACT"
