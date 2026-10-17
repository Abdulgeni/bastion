#!/usr/bin/env bash
# Phase B of the Vault bootstrap: enables AppRole, writes the payments policy,
# creates the payments role, generates role-id and a wrapped secret-id, and
# copies the wrapped secret-id into the shared var dir.
#
# Idempotent: safe to re-run against a fresh Vault container. Each `compose up`
# re-runs this on a new dev-Vault, which loses all in-memory state.
#
# Requires: VAULT_ADDR, VAULT_TOKEN (root), VAR_DIR (host-side path mounted
# into this container at the same location).
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
: "${VAR_DIR:=/var}"

wait_for_vault() {
  for i in $(seq 1 30); do
    if vault status >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "vault did not become ready in 30s" >&2
  return 1
}

wait_for_vault

if vault auth list -format=json | grep -q '"approle/"'; then
  echo "approle already enabled"
else
  vault auth enable approle
fi

vault policy write bastion-payments "${VAR_DIR}/vault/policy.hcl"

vault write auth/approle/role/payments \
  token_policies=bastion-payments \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_num_uses=1 \
  secret_id_ttl=5m \
  >/dev/null

ROLE_ID=$(vault read -field=role_id auth/approle/role/payments/role-id)
echo -n "${ROLE_ID}" > "${VAR_DIR}/vault/role-id"
chmod 600 "${VAR_DIR}/vault/role-id"

# Wrap the secret-id. `-wrap-ttl` produces a single-use wrapping token that the
# payments container unwraps once at boot; the resulting secret_id is what it
# uses for future logins, and that is what has `secret_id_num_uses=1` above.
vault write -wrap-ttl=60s -f auth/approle/role/payments/secret-id \
  -format=json | jq -r '.wrap_info.token' > "${VAR_DIR}/vault/wrapped-secret-id"
chmod 600 "${VAR_DIR}/vault/wrapped-secret-id"

echo "vault bootstrap complete"
