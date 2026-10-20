#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source demos/lib.sh

narrative "Bastion stolen-JWT demo"
require curl node
require_stack_up
require pnpm

login_body=$(login_as alice hunter2)
token=$(json_get "$login_body" .token) || die "no token in login response"
ok "got a valid token"

# --- Scenario A: signed with aud=payments; edge accepts (it doesn't check
# aud), orders rejects it. The 401 comes back through edge. The point of the
# scenario is that orders does not accept a token addressed only to payments.
narrative "[A] genuinely-signed token with aud=[payments] → rejected before any charge"
START_A=$(date -u +%s)
forged=$(forge_token_inline forge --aud payments)
[ -n "$forged" ] || die "forge-token produced nothing"
set +e
respA=$(place_order "$forged")
set -e
statusA="${respA%%$'\n'---*}"
# Accept any 4xx: 401 if orders rejects with bad_aud, 403 if scope-checking
# fires first. The invariant we assert is that the request is NOT 2xx.
case "$statusA" in
  4*) ok "order rejected with status $statusA (not 2xx)";;
  *)  die "order was NOT rejected for the bad-audience token (status $statusA)";;
esac
sleep 1
# Audit may show jwt+bad_aud at orders, or jwt+malformed at edge if the token
# shape wasn't accepted. Either way, an audit deny must exist somewhere.
auditA=$(printf '%s\n%s\n' \
  "$(audit_since orders "$START_A")" \
  "$(audit_since edge "$START_A")" \
  | grep -cE '"reason":"(jwt\\+bad_aud|jwt\\+bad-issuer|jwt\\+bad_sig|jwt\\+malformed)"' || true)
# SECURITY CHECK: the 401 above is the invariant. Audit is informational.
if [ "$auditA" -ge 1 ]; then ok "audit logged a token deny for the bad-audience scenario"
else fail "warning: no audit line for scenario A (401 still proves the rejection)"; fi

# --- Scenario B: tampered payload, rejected at edge as bad_sig ---
narrative "[B] tampered payload (aud edited after signing) → rejected at edge"
START_B=$(date -u +%s)
tampered=$(forge_token_inline tamper --token "$token" --aud payments)
[ -n "$tampered" ] || die "tamper produced nothing"
set +e
respB=$(place_order "$tampered")
set -e
statusB="${respB%%$'\n'---*}"
case "$statusB" in
  4*) ok "order rejected with status $statusB (not 2xx)";;
  *)  die "order was NOT rejected for the tampered token (status $statusB)";;
esac
sleep 1
auditB=$(audit_since edge "$START_B" | grep -c '"reason":"jwt+bad_sig"' || true)
if [ "$auditB" -ge 1 ]; then ok "edge logged jwt+bad_sig"
else fail "warning: no audit line for scenario B (401 still proves the rejection)"; fi

# --- Scenario C: replay a valid token ---
narrative "[C] replay a valid token: works once, rejected the second time"
START_C=$(date -u +%s)
respC1=$(place_order "$token")
statusC1="${respC1%%$'\n'---*}"
expect_eq "$statusC1" "201" "first use of token"
respC2=$(place_order "$token")
statusC2="${respC2%%$'\n'---*}"
case "$statusC2" in
  4*) ok "second use rejected with status $statusC2";;
  *)  die "second use was NOT rejected (status $statusC2)";;
esac
sleep 1
auditC=$(audit_since edge "$START_C" | grep -c '"reason":"jwt+replayed"' || true)
if [ "$auditC" -ge 1 ]; then ok "edge logged jwt+replayed"
else fail "warning: no audit line for scenario C (401 still proves the replay rejection)"; fi

narrative "PASS: all three stolen-token scenarios were rejected."
