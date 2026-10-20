# Bastion

A reference implementation of a zero-trust internal service mesh: SPIFFE/mTLS between services, short-lived JWTs with per-service replay protection, Vault-derived API keys, structured audit logging, Prometheus metrics, and a fully wired local stack (Docker Compose) with a Kubernetes + Istio mapping.

This is not a production system. It is a working, end-to-end demonstration of the seven NIST SP 800-207 zero-trust tenets, with the gaps documented honestly in `docs/architecture.md`.

## What works today

- Four services (`edge`, `orders`, `inventory`, `payments`) running in containers
- A dev CA that mints Ed25519 certs with SPIFFE URI SANs
- mTLS on every internal hop, with server-identity verification on both sides
- Ed25519 JWT issuance at edge, verification at every service, single-use `jti` replay tracking
- Vault-derived API key for `payments`, refreshed on a timer, fail-closed
- Structured audit events to stdout and `var/audit/<service>.log`
- Four Prometheus metrics on each service management port
- Four demo scripts that prove the security properties end to end

## Quick start

Prerequisites: Docker, Docker Compose v2, Node 20, pnpm 9, bash.

```bash
pnpm install
make up              # starts the stack; waits for all services to be healthy
make demo            # happy path: login -> order -> 4 allow audit lines
make demo-rogue      # topology segmentation blocks an attacker
make demo-stolen-jwt # three attack tokens are rejected
make demo-vault-rotation # Vault key rotates, no key leak
make down            # stop
```

## Commands

Run `make help` for the full list. The most important ones:

| Command | What it does |
|---|---|
| `make up` | Start the stack (init -> vault -> four services) |
| `make demo` | Happy-path end-to-end demo |
| `make demo-rogue` | Attacker demo: topology + identity checks |
| `make demo-stolen-jwt` | Three stolen-JWT scenarios |
| `make demo-vault-rotation` | Vault key rotation, no key leak |
| `make metrics <svc>` | Read `/metrics` from one service |
| `make audit-tail` | Tail all four audit logs |
| `make rotate-certs` | Re-issue every service cert (CA unchanged) |
| `make rotate-jwt` | Rotate edge JWT signing key |
| `make vault-reauth` | Re-issue the payments wrapped secret-id |
| `make ci` | `typecheck && lint && test` |

## Layout

```
apps/          four NestJS services (edge, orders, inventory, payments)
libs/bastion-common/  shared libraries (mTLS, identity, clock, random, config, JWT, audit, metrics)
scripts/       dev CA + certs, JWT keys, Vault bootstrap, forge-token
demos/         four end-to-end demo scripts
docker/        init image, rogue image
k8s/           Kubernetes + Istio manifests (documented target)
tests/         cross-service e2e test
var/           generated at runtime: CA, certs, JWT keys, audit logs (gitignored)
```

## Security properties demonstrated

- **mTLS everywhere**: every internal hop requires a client cert signed by the dev CA, with the expected SPIFFE ID for the caller.
- **Identity from the cert, not the network**: services identify callers by the URI SAN in the client cert, not by IP.
- **JWT with single-use jti**: tokens have a 5-minute TTL, per-service replay caches, and `aud`-scoped audiences.
- **Fail-closed on missing key material**: a service refuses to start without a valid CA, cert, JWT key, or Vault token.
- **Rotation is observable**: `make demo-vault-rotation` proves the payments key rotates and no full key appears in logs or on disk.

## Tests and CI

```bash
pnpm typecheck && pnpm lint && pnpm test
```

37 suites, ~300 tests. CI runs the same command on Ubuntu 24.04 (`.github/workflows/ci.yml`).

## Docs

- `docs/architecture.md` - trust boundaries, NIST SP 800-207 mapping, and honest gaps
- `k8s/README.md` - Compose to Kubernetes mapping (documented target, not verified)
- `var/` is generated at runtime and gitignored

## License

Private. Demonstration code only.
