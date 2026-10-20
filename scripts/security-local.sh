#!/usr/bin/env bash
# Run every security scanner that CI runs, on the host, before pushing.
# Requires: docker, node, pnpm. Gitleaks and Trivy run as containers.
set -uo pipefail
EXIT=0
say() { printf "\n\033[36m==> %s\033[0m\n" "$*"; }
ok()  { printf "\033[32m  ok %s\033[0m\n" "$*"; }
bad() { printf "\033[31m  FAIL %s\033[0m\n" "$*" >&2; EXIT=1; }
require() { for c in "$@"; do command -v "$c" >/dev/null 2>&1 || { echo "missing: $c" >&2; exit 2; }; done; }
MSYS_NO_PATHCONV=1 export MSYS_NO_PATHCONV
require docker node pnpm

say "Secret scan (Gitleaks, full repo and history)"
if docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:v8.28.0 \
     detect --source=/repo --redact --no-banner; then
  ok "no secrets found"
else
  bad "secrets found (see above)"
fi

say "Dependency scan (pnpm audit --prod, HIGH and CRITICAL)"
if pnpm audit --prod --audit-level=high >/tmp/audit.out 2>&1; then
  ok "no HIGH or CRITICAL advisories"
else
  sed -e 's/^/  /' /tmp/audit.out
  bad "HIGH or CRITICAL advisories (see above)"
fi

say "Container image scan (Trivy, CRITICAL only)"
if [ "${SCAN_CONTAINERS:-0}" != "1" ]; then
  say "skipped (set SCAN_CONTAINERS=1 to run locally; CI does this on Linux)"
elif docker image inspect bastion-edge:dev >/dev/null 2>&1; then
  for app in edge orders inventory payments; do
    if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
         aquasec/trivy:latest image -q \
           --severity CRITICAL --ignore-unfixed --exit-code 1 \
           "bastion-$app:dev" 2>&1 | tail -30; then
      ok "$app image clean"
    else
      bad "$app image has CRITICAL CVEs (see above)"
    fi
  done
else
  say "skipped (bastion images not built; run 'make up' first)"
fi

# IaC scan is opt-in via SCAN_IAC=1. Same reason as container scan:
# on Docker Desktop for Windows, Trivy redownloads its DB on every docker
# run because we don't persist ~/.cache/trivy into the container. On Linux
# (CI) this takes seconds. Local runs stay fast.
say "IaC scan (Trivy config, HIGH and CRITICAL)"
if [ "${SCAN_IAC:-0}" != "1" ]; then
  say "skipped (set SCAN_IAC=1 to run locally; CI does this on Linux)"
else
  docker run --rm -v "$PWD":/src aquasec/trivy:latest config -q \
    --severity HIGH,CRITICAL --exit-code 1 /src 2>&1 | tail -40
  rc=$?
  if [ "$rc" -eq 0 ]; then ok "no HIGH or CRITICAL IaC findings"
  else bad "IaC findings (see above)"; fi
fi

echo ""
if [ "$EXIT" -eq 0 ]; then printf "\033[32mAll local security checks passed.\033[0m\n"
else printf "\033[31mSome local security checks failed.\033[0m\n"; fi
exit "$EXIT"
