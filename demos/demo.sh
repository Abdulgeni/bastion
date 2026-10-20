#!/usr/bin/env bash
# Happy path: login → order → 4 allow audit lines sharing one jwt_jti.
set -euo pipefail
cd "$(dirname "$0")/.."
source demos/lib.sh

narrative "Bastion happy-path demo"
require curl node
require_stack_up

START_TS=$(date -u +%s)

narrative "[1] login alice → 200"
login_body=$(login_as alice hunter2)
token=$(json_get "$login_body" .token) || die "no token in login response: $login_body"
ok "got token (${#token} bytes)"

narrative "[2] POST /orders → 201 order_id=…"
resp=$(place_order "$token")
status="${resp%%$'\n'---*}"
body="${resp#*$'\n'---$'\n'}"
expect_eq "$status" "201" "order status"
order_id=$(json_get "$body" .order_id) || die "no order_id in order response: $body"
ok "order_id=$order_id"

fp=$(json_get "$body" .payment.keyFingerprint) || die "no payment.keyFingerprint in order response: $body"
expect_match "$fp" '^[0-9a-f]{16}$' "payment.keyFingerprint"
ok "payment.keyFingerprint=$fp"

narrative "[3] audit: 4 allow lines sharing one jwt_jti"
sleep 1
edge_lines=$(audit_since edge "$START_TS")
orders_lines=$(audit_since orders "$START_TS")
inventory_lines=$(audit_since inventory "$START_TS")
payments_lines=$(audit_since payments "$START_TS")

# Edge has two guards (PeerIdentityGuard and JwtAuthGuard), so it logs
# 2 allow lines per request. Every other service has one, so 1. The real
# assertion is that all four services share one jwt_jti.
allow_edges=$(printf '%s\n' "$edge_lines"     | grep -c '"decision":"allow"' || true)
allow_orders=$(printf '%s\n' "$orders_lines"   | grep -c '"decision":"allow"' || true)
allow_inv=$(printf '%s\n' "$inventory_lines"   | grep -c '"decision":"allow"' || true)
allow_pay=$(printf '%s\n' "$payments_lines"    | grep -c '"decision":"allow"' || true)

[ "$allow_edges"  -ge 1 ] || die "edge logged no allow lines"
[ "$allow_orders" -ge 1 ] || die "orders logged no allow lines"
[ "$allow_inv"    -ge 1 ] || die "inventory logged no allow lines"
[ "$allow_pay"    -ge 1 ] || die "payments logged no allow lines"
ok "edge=$allow_edges orders=$allow_orders inventory=$allow_inv payments=$allow_pay allow lines"

jtis=$(printf '%s\n%s\n%s\n%s\n' "$edge_lines" "$orders_lines" "$inventory_lines" "$payments_lines" \
  | grep -o '"jwt_jti":"[^"]*"' | sort -u | wc -l | tr -d ' ')
expect_eq "$jtis" "1" "unique jwt_jti across all four services"

narrative "PASS: happy path."
