#!/usr/bin/env bash
# Run every security scanner that CI runs, on the host, before pushing.
# Requires: docker, node, pnpm. Gitleaks and Trivy run as containers, so
# no host-installed scanners are needed except pnpm itself.
#
# Each scanner runs independently — a finding in one does not stop the
# others. Exit code 1 if any scanner fails, 0 if all pass.
set -uo pipefail

EXIT=0
say() { printf "\n\033[36m==> %s\033[0m\n" "$*"; }
ok()  { printf "\033[32m  ok %s\033[0m\n" "$*"; }
bad() { printf "\033[31m  FAIL %s\033[0m\n" "$*" >&2; EXIT=1; }
require() { for c in "$@"; do command -v "$c" >/dev/null 2>&1 || { echo "missing: $c" >&2; exit 2; }; done; }

require docker node pnpm

say "Secret scan (Gitleaks, full repo and history)"
if docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:v8.28.0 \
     detect --source=/repo --redact --no-banner; then
  ok "no secrets found"
else
  bad "secrets found (see above)"
fi

say "Dependency scan (pnpm audit --prod, HIGH and CRITICAL)"
if pnpm audit --prod --audit-level=high >/dev/null 2>&1; then
  ok "no HIGH or CRITICAL advisories"
else
  pnpm audit --prod --audit-level=high || true
  bad "HIGH or CRITICAL advisories"
fi

say "Container image scan (Trivy, CRITICAL only)"
if docker image inspect bastion-edge:dev >/dev/null 2>&1; then
  for app in edge orders inventory payments; do
    if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
         aquasec/trivy:latest image \
           --severity CRITICAL --ignore-unfixed --exit-code 1 \
           --no-progress "bastion-$app:dev" >/dev/null 2>&1; then
      ok "$app image clean"
    else
      bad "$app image has CRITICAL CVEs"
    fi
  done
else
  say "skipped (bastion images not built; run 'make up' first)"
fi

say "IaC scan (Trivy config, HIGH and CRITICAL)"
if docker run --rm -v "$PWD":/src aquasec/trivy:latest config \
     --severity HIGH,CRITICAL --exit-code 1 --no-progress /src >/dev/null 2>&1; then
  ok "no HIGH or CRITICAL IaC findings"
else
  bad "IaC findings (see above)"
fi

echo ""
if [ "$EXIT" -eq 0 ]; then
  printf "\033[32mAll local security checks passed.\033[0m\n"
else
  printf "\033[31mSome local security checks failed.\033[0m\n"
fi
exit "$EXIT"
