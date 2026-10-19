#!/usr/bin/env bash
# Re-issue a wrapped secret-id for the payments role. This is the manual fix
# for `make vault-reauth` from Step 1's F5: a lone `docker compose restart
# payments` spends the current wrap, and a fresh one is needed.
#
# Requires: VAULT_ADDR, VAULT_TOKEN (root), VAR_DIR.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
if [ -z "${VAULT_TOKEN:-}" ] && [ -n "${VAULT_TOKEN_FILE:-}" ] && [ -r "${VAULT_TOKEN_FILE}" ]; then
  VAULT_TOKEN="$(tr -d '\n' < "${VAULT_TOKEN_FILE}")"
  export VAULT_TOKEN
fi
: "${VAULT_TOKEN:?VAULT_TOKEN or VAULT_TOKEN_FILE must be set and readable}"
: "${VAR_DIR:=/var}"

vault write -wrap-ttl=60s -f auth/approle/role/payments/secret-id \
  -format=json | jq -r '.wrap_info.token' > "${VAR_DIR}/vault/wrapped-secret-id"
chmod 600 "${VAR_DIR}/vault/wrapped-secret-id"

echo "wrapped secret-id re-issued; restart payments to consume it"
