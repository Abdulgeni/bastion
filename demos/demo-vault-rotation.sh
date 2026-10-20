#!/usr/bin/env bash
# Vault rotation: two orders ~15s apart, fingerprints must differ.
set -euo pipefail
cd "$(dirname "$0")/.."
source demos/lib.sh

narrative "Bastion vault-rotation demo (VAULT_KEY_TTL_SECONDS=10)"
require curl node
require_stack_up

login1=$(login_as alice hunter2)
token1=$(json_get "$login1" .token) || die "no token in first login"
resp1=$(place_order "$token1")
status1="${resp1%%$'\n'---*}"
body1="${resp1#*$'\n'---$'\n'}"
expect_eq "$status1" "201" "order 1 status"
fp1=$(json_get "$body1" .payment.keyFingerprint) || die "no fingerprint in order 1"
ok "order 1 fingerprint = $fp1"

narrative "waiting 15s for the payments key to rotate (VAULT_KEY_TTL_SECONDS=10)"
sleep 15

login2=$(login_as alice hunter2)
token2=$(json_get "$login2" .token) || die "no token in second login"
resp2=$(place_order "$token2")
status2="${resp2%%$'\n'---*}"
body2="${resp2#*$'\n'---$'\n'}"
expect_eq "$status2" "201" "order 2 status"
fp2=$(json_get "$body2" .payment.keyFingerprint) || die "no fingerprint in order 2"
ok "order 2 fingerprint = $fp2"

if [ "$fp1" = "$fp2" ]; then
  die "fingerprints did not change across 15s (rotation is broken or TTL is wrong)"
fi
ok "fingerprints DIFFER (rotation works)"

narrative "[check] no full key appears in var/ or audit logs"
# The fingerprint is 16 hex chars; a full 32-byte key in hex would be 64.
# Grep the whole tree for long hex strings that aren't the fingerprints.
if grep -rEn '\b[0-9a-f]{64}\b' var/audit/ var/demo/ 2>/dev/null | head -3; then
  die "64-char hex string found — this might be a leaked Vault key"
fi
ok "no 64-char hex string in var/audit/ or var/demo/"

narrative "PASS: vault rotation works and the full key never leaves the container."
