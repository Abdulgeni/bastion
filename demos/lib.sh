#!/usr/bin/env bash
# Shared helpers for Bastion demos. Source this; do not execute it directly.
#
# Requires: curl (Linux, via the rogue container), node (host), docker compose.
# Host curl is NOT used because on Windows it uses Schannel, which rejects the
# dev cert even with -k. All HTTP calls go through the rogue container (Linux
# curl, attached to bastion-frontend), which is started lazily.

set -euo pipefail

# ---- output ----
if [ -t 1 ]; then
  C_RESET='\033[0m'; C_GREEN='\033[32m'; C_RED='\033[31m'; C_CYAN='\033[36m'; C_BOLD='\033[1m'
else
  C_RESET=''; C_GREEN=''; C_RED=''; C_CYAN=''; C_BOLD=''
fi

narrative() { printf "${C_CYAN}%s${C_RESET}\n" "$*"; }
ok()        { printf "${C_GREEN}  ✓ %s${C_RESET}\n" "$*"; }
fail()      { printf "${C_RED}  ✗ %s${C_RESET}\n" "$*" >&2; }
die()       { fail "$*"; exit 1; }

expect_eq() {
  local actual="$1" expected="$2" label="$3"
  if [ "$actual" = "$expected" ]; then ok "$label = $expected"; else die "$label expected '$expected', got '$actual'"; fi
}

expect_contains() {
  local haystack="$1" needle="$2" label="$3"
  if printf '%s' "$haystack" | grep -qF "$needle"; then ok "$label contains '$needle'"; else die "$label does not contain '$needle': $haystack"; fi
}

expect_match() {
  local haystack="$1" pattern="$2" label="$3"
  if printf '%s' "$haystack" | grep -qE "$pattern"; then ok "$label matches /$pattern/"; else die "$label does not match /$pattern/: $haystack"; fi
}

require() {
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"; done
}

# ---- JSON parsing without jq (uses host node) ----
# json_get <json> <path> — path like .token or .payment.keyFingerprint
json_get() {
  local json="$1" path="$2"
  node -e '
    const [raw, path] = process.argv.slice(1);
    let v;
    try { v = JSON.parse(raw); } catch { process.stderr.write("not JSON: "+raw+"\n"); process.exit(2); }
    for (const p of path.replace(/^\./,"").split(".")) v = (v == null) ? undefined : v[p];
    if (v === undefined) process.exit(1);
    process.stdout.write(typeof v === "string" ? v : JSON.stringify(v));
  ' "$json" "$path"
}

# ---- HTTP via the rogue container (Linux curl, on bastion-frontend) ----
EDGE_INTERNAL_URL="${EDGE_INTERNAL_URL:-https://edge:8080}"

ensure_curl_helper() {
  # Start the rogue container lazily if it isn't running. It's on
  # bastion-frontend (with edge) and has curl.
  if ! docker compose --profile rogue ps --format json 2>/dev/null | grep -q '"Service":"rogue"'; then
    docker compose --profile rogue up -d rogue >/dev/null 2>&1 || true
    sleep 1
  fi
}

# curl_in <method> <path> <body-or-empty> <token-or-empty>
curl_in() {
  local method="$1" path="$2" body="$3" token="$4"
  ensure_curl_helper
  local args=(-sS -k --max-time 10 -X "$method" "$EDGE_INTERNAL_URL$path")
  if [ -n "$body" ]; then args+=(-H 'content-type: application/json' -d "$body"); fi
  if [ -n "$token" ]; then args+=(-H "authorization: Bearer $token"); fi
  docker compose exec -T rogue curl "${args[@]}" 2>/dev/null
}

login_as() {
  curl_in POST /login "{\"username\":\"$1\",\"password\":\"$2\"}" ""
}

# place_order returns "status\n---\nbody"
place_order() {
  local token="$1" sku="${2:-sku-1}" qty="${3:-1}" amount="${4:-100}"
  ensure_curl_helper
  local raw
  raw=$(docker compose exec -T rogue curl -sS -k --max-time 10 \
    -w $'\n__STATUS__%{http_code}' -X POST "$EDGE_INTERNAL_URL/orders" \
    -H "authorization: Bearer $token" \
    -H 'content-type: application/json' \
    -d "{\"sku\":\"$sku\",\"quantity\":$qty,\"amount\":$amount}" 2>/dev/null)
  local status="${raw##*__STATUS__}"
  local body="${raw%$'\n'__STATUS__*}"
  printf '%s\n---\n%s\n' "$status" "$body"
}

# ---- audit helpers ----
# audit_since <service> <epoch-seconds> — print matching JSON lines
audit_since() {
  local service="$1" since="$2"
  local path="var/audit/${service}.log"
  [ -f "$path" ] || { echo ""; return 0; }
  node -e '
    const fs = require("fs");
    const [path, sinceStr] = process.argv.slice(1);
    const since = Number(sinceStr);
    const lines = fs.readFileSync(path, "utf8").split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        const ms = Date.parse(obj.ts);
        if (Number.isFinite(ms) && ms / 1000 >= since) console.log(line);
      } catch { /* skip */ }
    }
  ' "$path" "$since"
}

# ---- env checks ----
require_docker() {
  require docker
  docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
}

require_stack_up() {
  require_docker
  local running
  running=$(docker compose ps --services --filter "status=running" 2>/dev/null | wc -l | tr -d ' ')
  [ "${running:-0}" -ge 5 ] || die "expected 5 services running, got ${running:-0}. Run 'docker compose up -d --wait' first."
}

# ---- forge-token via container (has access to the jwt-keys named volume) ----
# forge_token_inline <forge|tamper> [args...]
forge_token_inline() {
  docker compose run --rm --no-deps --entrypoint sh bastion-init -c \
    "pnpm exec ts-node scripts/forge-token.ts \$*" -- "$@" 2>/dev/null
}
