#!/usr/bin/env bash
# Start Anvil with a Base Sepolia fork
# All DelegationManager + enforcer contracts are already deployed on Base Sepolia
set -euo pipefail

FOUNDRY_BIN="${HOME}/.foundry/bin"
PORT="${ANVIL_PORT:-8545}"

echo "🔨 Starting Anvil (Base Sepolia fork) on port ${PORT}..."
exec "${FOUNDRY_BIN}/anvil" \
  --fork-url https://sepolia.base.org \
  --port "${PORT}" \
  --accounts 10 \
  --balance 10000 \
  --block-time 1
