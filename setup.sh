#!/usr/bin/env bash
# Aegis — one-command setup for casual users.
#
# Deploys the Aegis policy contract to a fresh account (or an existing one),
# initializes it with YOU as operator, and configures reviewer + guardian.
# Daily use after this is 100% from the dashboard (browser wallet).
#
# Usage:
#   ./setup.sh <your-near-account> <contract-account> [reviewer-account] [guardian-account]
# Examples:
#   ./setup.sh suisei.testnet aegis.svisei.testnet
#   ./setup.sh suisei.testnet aegis.svisei.testnet watchdog-reviewer-4d8a7f.testnet watchdog-guardian-4d8a7f.testnet
#
# Prerequisites: near-cli-rs on PATH, Rust-built watchdog.wasm (or build it), 
# your account funded on testnet (faucet: https://near-faucet.io).

set -euo pipefail

OPERATOR="${1:-}"
CONTRACT="${2:-}"
REVIEWER="${3:-}"
GUARDIAN="${4:-}"
NETWORK="testnet"
THRESHOLD="1"

if [[ -z "$OPERATOR" || -z "$CONTRACT" ]]; then
  echo "usage: ./setup.sh <your-near-account> <contract-account> [reviewer] [guardian]"
  exit 1
fi

WASM="contract/target/wasm32-unknown-unknown/release/watchdog.wasm"
if [[ ! -f "$WASM" ]]; then
  echo "watchdog.wasm not found at $WASM"
  echo "build it:  (cd contract && cargo build --target wasm32-unknown-unknown --release)"
  exit 1
fi

# 1. create contract account (funded by you)
echo "→ creating $CONTRACT (funded by $OPERATOR)"
near account create-account fund-existing "$CONTRACT" "$OPERATOR" "1 NEAR" network-config "$NETWORK" sign-with-keychain send

# 2. deploy code
echo "→ deploying contract code"
near contract deploy "$CONTRACT" use-file "$WASM" without-init-call network-config "$NETWORK" sign-with-keychain send

# 3. initialise with you as operator
echo "→ initializing (operator = $OPERATOR)"
near contract call-function as-transaction "$CONTRACT" new \
  json-args "{\"operator\":\"$OPERATOR\",\"guard_threshold\":$THRESHOLD}" \
  prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$OPERATOR" network-config "$NETWORK" sign-with-keychain send

# 4. reviewer + guardian (optional)
if [[ -n "$REVIEWER" ]]; then
  echo "→ appointing reviewer $REVIEWER"
  near contract call-function as-transaction "$CONTRACT" set_reviewer \
    json-args "{\"reviewer\":\"$REVIEWER\"}" \
    prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
    sign-as "$OPERATOR" network-config "$NETWORK" sign-with-keychain send
fi
if [[ -n "$GUARDIAN" ]]; then
  echo "→ adding guardian $GUARDIAN"
  near contract call-function as-transaction "$CONTRACT" guardian_add \
    json-args "{\"account\":\"$GUARDIAN\"}" \
    prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' \
    sign-as "$OPERATOR" network-config "$NETWORK" sign-with-keychain send
fi

echo "✅ Aegis is live at $CONTRACT (operator: $OPERATOR)"
echo "   Next: open the dashboard, connect your wallet, switch to:"
echo "   $CONTRACT"
