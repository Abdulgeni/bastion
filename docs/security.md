# Security pipeline

This document describes the security checks that run on every push and pull
request, what each one is for, and what constitutes a failure.

## Philosophy

The pipeline is a **control plane**, not a dashboard. It fails closed on risks
the project has decided are unacceptable, and warns on everything else. A
finding that is not acted on is worse than no finding — it trains people to
ignore the pipeline. So each scanner has a specific, documented gating policy.

| Scanner | Scope | Blocks build | Warns only |
|---|---|---|---|
| Gitleaks | Full repo, all history | Any detected secret | — |
| `pnpm audit --prod` | Production dependencies | HIGH or CRITICAL advisory | MODERATE, LOW, INFO |
| Semgrep (Step 13) | Application source | `ERROR` severity finding | `WARNING`, `INFO` |
| Trivy (Step 14) | Container images, k8s/IaC | `CRITICAL` CVE, `HIGH` IaC misconfig | everything else |

## Secret scanning (Gitleaks)

**What it does.** Scans the git history and the working tree for secrets:
API keys, tokens, private keys, passwords. Uses the upstream default ruleset
(260+ patterns) extended only by `.gitleaks.toml` at the repository root.

**Why the configuration is small.** `.gitleaks.toml` extends the default rules
and adds exactly one allowlist entry — `tests/fixtures/`. Every other directory
is scanned with no exceptions. Adding more allowlist entries requires a
documented reason in the file itself.

**Self-test.** The workflow contains a step that scans `tests/fixtures/`
*without* the allowlist and asserts that Gitleaks finds the AWS documentation
example key stored there. If that self-test fails, the whole job fails. This
matters because a mis-configured Gitleaks silently finds nothing and looks
green. The self-test proves the scanner is actually firing.

**What a finding looks like.** The job fails with a line per secret:

Finding: AWS_ACCESS_KEY_ID=AKIA...
Secret: AKIA...
RuleID: aws-access-token
File: <path>
Line: <n>

Rotate the credential, then remove it from the file. If it was committed, use
`git filter-repo` to purge it from history, then force-push the affected
branch — otherwise the next scan will find it again in the diff.

## Dependency scanning (`pnpm audit --prod`)

**What it does.** Queries the registry's advisory database for known
vulnerabilities in **production** dependencies. Development-only dependencies
(`jest`, `eslint`, `typescript`, `ts-node`) are out of scope: they never ship
in a container, so a CVE in them is an attack on the developer's laptop, not
on the deployed system.

**Gate.** HIGH and CRITICAL advisories fail the job. MODERATE and below are
logged in the step output but do not fail. The rationale: a project that gates
on every LOW advisory will spend all its time on low-risk transitive issues
and miss real ones. A project that gates on nothing will ship known-vulnerable
software. HIGH and CRITICAL is the sweet spot.

**Network failures vs. findings.** `pnpm audit --prod` exits non-zero both
when it finds vulnerabilities **and** when it cannot reach the registry. The
workflow distinguishes the two: if the JSON output is missing or empty, the
job exits with code 2 and a clear message ("likely a registry or network
failure"), not with a false-positive vulnerability.

## What runs where

| File | Trigger | What it runs |
|---|---|---|
| `.github/workflows/ci.yml` | push, PR | typecheck, lint, tests, shell syntax |
| `.github/workflows/security.yml` | push, PR | Gitleaks, `pnpm audit --prod` |

Semgrep (Step 13) and Trivy (Step 14) join `security.yml` as separate jobs.

## Hygiene observations surfaced by this step

- **`libs/bastion-common/package.json` lists `@nestjs/testing` as a runtime
  dependency.** It is only imported by specs. Moving it to `devDependencies`
  shrinks the deployed library and removes it from the audit surface. Small,
  safe change; deferred so Step 12 does not touch runtime code.
- **`pino-pretty` is a devDependency at the root** but `pino` is a runtime
  dependency of `libs/bastion-common`. That is correct: `pino-pretty` is only
  used for human-readable development logs.

## Running locally with `make security-local` (Step 15)

Every scanner that runs in CI can be run on the host before pushing:

```bash
make security-local
Each scanner runs independently — a finding in one does not stop the
others. Exit code is 1 if any scanner fails, 0 if all pass. Requires
Docker, node, and pnpm on the host; Gitleaks and Trivy run as containers
so no host-installed scanners are needed.

## Incident log

### 2026-10-20 — CA private key found in git history

**Discovery.** Running `make security-local` (Gitleaks) found five Ed25519
private key files committed in the initial commit `7e2a3ee`:

- `var2/ca/ca.key` (CA private key)
- `var2/certs/edge/key.pem`
- `var2/certs/orders/key.pem`
- `var2/certs/inventory/key.pem`
- `var2/certs/payments/key.pem`

These came from an early manual test run of `scripts/gen-certs.ts` that
wrote a second PKI tree at `var2/` before the `var/` layout was settled.
That tree was not gitignored at the time and got committed with the first
change to the repository.

**Impact.** Anyone who clones the repository has those five private keys.
`var2/ca/ca.key` can mint certificates that any service trusting the
`var2` CA would accept.

**Not impacted.** The running Compose stack uses `var/`, not `var2/`. The
two CAs are independent. No live service trusts the `var2` CA, so the
leaked keys grant no access to the running system.

**Response.**

1. `var2/` added to `.gitignore`, removed from disk.
2. History purged with `git filter-repo --invert-paths --path var2/`. All
   commits from the initial commit onward get new SHAs. Old objects remain
   on GitHub's servers until garbage-collected but are no longer reachable
   from any ref.
3. CI's `secret-scan` job (Gitleaks) now scans the clean history. Zero
   findings expected.
4. The verifier wrapper in an earlier commit message ("0 findings locally
   now") was incorrect: `make ... | tee` returns `tee`'s exit code, not
   `make`'s. The scan did fail with 5 findings. Corrected by this incident
   entry.

**Prevention.**

- Any directory matching `var*` must be added to `.gitignore` in the same
  change that creates it. A defensive pattern (`var*/`) would have caught
  this on day one.
- `make security-local` is now a pre-push check. If it had existed on the
  initial commit, the push would have been blocked.
