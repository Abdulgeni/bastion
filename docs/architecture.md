# Bastion architecture

Trust boundaries, the seven NIST SP 800-207 tenets applied here, and the gaps that remain.

## Trust boundaries

- **TB-0: host or external clients -> edge.** Server-auth TLS only. Users authenticate with a JWT. No client cert is expected.
- **TB-1: edge -> orders.** mTLS plus JWT. Edge presents its client cert and forwards the user token; orders verifies both.
- **TB-2: orders -> inventory, orders -> payments.** mTLS only. The caller is a workload, not a user.
- **TB-3: payments -> vault.** Plain HTTP in Compose (dev Vault). AppRole login, wrapped secret-id.
- **TB-4: management plane.** `/healthz`, `/metrics`, `/.well-known/jwks.json`. Plain HTTP on `internal: true` network in Compose. STRICT mTLS in k8s.

## NIST SP 800-207 tenets

### 1. All data sources and computing services are resources

Each service, route, and the Vault key is a distinctly named resource. Every route declares `@AllowCallers(...)` plus a required scope. Audit events carry `resource: "POST /charge"`.

Gap: static inventory of four services. Real estates need discovery and asset management.

### 2. All communication is secured regardless of network location

`libs/bastion-common/mtls` forces mTLS on every internal data-plane hop, including same-network calls. Edge client-facing is TLS.

Gap: management plane is plaintext in Compose (internal network only). Vault dev mode is plaintext.

### 3. Access is granted per session / per connection

Each mTLS handshake is fresh. JWT TTL is 5 minutes and `jti` is single-use per service. Payments key rotates every 10s.

Gap: replay cache is in-process. Replicas would not share it. No session revocation list.

### 4. Access is decided by dynamic policy

`PeerIdentityGuard` combines peer SPIFFE ID, route allowlist, cert validity window, JWT `aud`, and per-endpoint scope. All must pass.

Gap: policy is static code and config. No behavioral or environmental signals.

### 5. Integrity and security posture of assets is monitored

Services refuse to start with missing or invalid CA, certs, JWT keys, or Vault key. Certs checked against the Clock on every request. `rejected_expired` is measured.

Gap: no workload attestation (SPIRE, TPM), image signing, or vulnerability scanning. Identity comes from files, not attested runtime properties.

### 6. Authn and authz are dynamic and strictly enforced before access

Handshake failures audited via `tlsClientError`. Identity, JWT, and scope failures return 401/403 before the handler. JWKS outage fails closed (503).

Gap: edge is both issuer and first verifier, so a compromised edge can mint arbitrary tokens. A real deployment separates the STS/IdP.

### 7. Collect as much state as possible to improve posture

Structured audit to stdout and `var/audit/<svc>.log`. Four Prometheus metrics per service. `make audit-tail`.

Gap: no SIEM, anomaly detection, alerting, or feedback loop into policy.

## Design flaws found and addressed

These were surfaced during the build and are documented with the mitigation implemented:

- **F1. Single-network topology cannot enforce the call graph.** Mitigated: five networks (frontend, inventory, payments, vault, mgmt) with fixed IPAM.
- **F2. Shared mgmt network re-opens the data plane.** Mitigated: `DATA_BIND_ADDR` and `MGMT_BIND_ADDR` env vars; each service binds its data listener to its inter-service network IP, so it is unreachable on mgmt. Mgmt listens on 0.0.0.0 but is isolated by `internal: true`.
- **F3. Two-Nest-app pattern breaks shared state.** Mitigated: one Nest app per service plus a raw `http.createServer` for mgmt.
- **F4. Vault policy capability wrong (`read` instead of `update` on `sys/tools/random`).** Mitigated: `update` in `scripts/vault-bootstrap.sh` and in `init.ts`.
- **F5. Vault bootstrap circular; wrapped secret-id is single-use.** Mitigated: three-phase init chain; `make vault-reauth` re-issues the wrap.
- **F6. Single-use `jti` limits each login to one order.** Documented; demos log in per order.
- **F7. SPIFFE URI SANs break Node default hostname verification.** Mitigated: certs carry DNS SANs too; outbound clients use a custom `checkServerIdentity`.
- **F8. Replay cache LRU could evict live entries.** Mitigated: TTL map with hard cap; full cache returns 503 `replay+cache_full` and never evicts.

## Known gaps (documented, not mitigated in Compose)

- **Plaintext on management plane.** Compose uses `internal: true` and no host route, but no mTLS. k8s STRICT mTLS closes this.
- **Plaintext between payments and Vault.** Compose dev Vault. Production would use Vault with TLS or Vault Agent injection.
- **JWKS on mgmt is plaintext.** Anyone on `bastion-mgmt` can swap keys. Istio mTLS fixes this in k8s.
- **No session revocation.** A valid JWT is valid until `exp`.
- **No workload attestation.** Identity comes from files, not from a SPIRE-style attestation.
- **Replay cache is per-process.** Replicas do not share it.

## Deterministic builds

All key material (CA, service certs, JWT signing keys, Vault role-id, wrapped secret-id) is generated from the injected `RandomSource`; all validity times from the `Clock`. A fixed seed plus a fixed clock produces byte-identical output. Tests exploit this.

## What CI verifies, and what it does not

CI runs `pnpm typecheck`, `pnpm lint`, `pnpm test` on Ubuntu 24.04. That covers:

- Key derivation, cert issuance, JWT sign/verify, JWKS cache, replay cache, audit, metrics
- Peer identity checks, JWT checks, scope checks, all four services' modules
- The end-to-end test (real mTLS, real JWTs, real JWKS)
- The demos' shell syntax

CI does not run the containers. Every k8s manifest is a documented target, not a verified deployment. The Compose stack is the reference. `make up` on your machine is what verifies the containers start and stay healthy.
