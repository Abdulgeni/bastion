<div align="center">

<a href="https://github.com/Abdulgeni/bastion">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&height=220&section=header&text=Bastion&fontSize=100&fontColor=ffffff&animation=twinkling&fontAlignY=38&desc=Zero-Trust%20Service%20Mesh&descAlignY=60&descSize=22" alt="Bastion header" />
</a>

<a href="https://git.io/typing-svg">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=3500&pause=800&color=667EEA&center=true&vCenter=true&multiline=true&width=850&height=140&lines=SPIFFE+mTLS+on+every+internal+hop;Ed25519+JWTs+with+single-use+replay+protection;Vault-derived+API+keys%2C+fail-closed;Four+end-to-end+demos%2C+all+green+%E2%9C%93;Five+networks%2C+zero+trust%2C+documented+gaps" alt="Typing SVG" />
</a>

<br/>

<img src="https://img.shields.io/badge/containers-5%20healthy-22c55e?style=for-the-badge&logo=docker&logoColor=white" alt="containers" />
<img src="https://img.shields.io/badge/tests-296%20passing-22c55e?style=for-the-badge&logo=jest&logoColor=white" alt="tests" />
<img src="https://img.shields.io/badge/demos-4%2F4%20passing-8b5cf6?style=for-the-badge" alt="demos" />
<img src="https://img.shields.io/badge/NIST%20800--207-7%2F7%20tenets-6366f1?style=for-the-badge" alt="nist" />

<br/><br/>

<img src="https://img.shields.io/badge/Node.js-20-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="node" />
<img src="https://img.shields.io/badge/TypeScript-5.4-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="typescript" />
<img src="https://img.shields.io/badge/NestJS-10-E0234E?style=for-the-badge&logo=nestjs&logoColor=white" alt="nestjs" />
<img src="https://img.shields.io/badge/Docker_Compose-v2-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="docker" />
<img src="https://img.shields.io/badge/Kubernetes_Istio-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="k8s" />
<img src="https://img.shields.io/badge/Vault-1.17-FFEC6E?style=for-the-badge&logo=vault&logoColor=black" alt="vault" />
<img src="https://img.shields.io/badge/Ed25519-22c55e?style=for-the-badge" alt="ed25519" />

</div>

---

<div align="center">

### 🌐 [Overview](#-overview) · 🏛 [Architecture](#-architecture) · ✨ [Features](#-features) · 🚀 [Quick Start](#-quick-start) · 🎬 [Demos](#-demos) · 🔒 [Security](#-security-model) · 📚 [Docs](#-documentation)

</div>

---

## 🌐 Overview

**Bastion** is a reference implementation of a zero-trust internal service mesh. Every hop between services is authenticated with **SPIFFE identity**, encrypted with **mTLS**, and authorized by **short-lived JWTs** with **single-use replay protection**. Payments holds no long-lived secret — its API key is derived from **Vault** and rotates on a timer, fail-closed.

Four services (`edge`, `orders`, `inventory`, `payments`) run **locally in Docker Compose** across five networks, and the same topology is **documented for Kubernetes + Istio**.

> ⚠️ **This is not a production system.** It is a working, end-to-end demonstration of the seven [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) zero-trust tenets, with every gap documented in [`docs/architecture.md`](docs/architecture.md).

---

## 🏛 Architecture

### Data flow and trust boundaries

```mermaid
flowchart LR
    C([Client])
    EDGE[**edge**<br/>:8080]
    ORD[**orders**<br/>:8443]
    INV[**inventory**<br/>:8444]
    PAY[**payments**<br/>:8445]
    VAULT[(Vault<br/>:8200)]
    ROGUE[⚠️ rogue]

    C -- "TLS + JWT<br/>TB-0" --> EDGE
    EDGE -- "mTLS + JWT<br/>TB-1" --> ORD
    ORD -- "mTLS<br/>TB-2" --> INV
    ORD -- "mTLS<br/>TB-2" --> PAY
    PAY -- "AppRole<br/>TB-3" --> VAULT

    ROGUE -. "✗ blocked" .-> PAY
    ROGUE -. "✗ blocked" .-> ORD

    classDef edge fill:#667eea,stroke:#4c51bf,color:#fff
    classDef svc fill:#764ba2,stroke:#5a3673,color:#fff
    classDef vault fill:#f59e0b,stroke:#b45309,color:#000
    classDef rogue fill:#ef4444,stroke:#b91c1c,color:#fff
    classDef host fill:#1e293b,stroke:#0f172a,color:#f1f5f9

    class EDGE edge
    class ORD,INV,PAY svc
    class VAULT vault
    class ROGUE rogue
    class C host
```

### Layers

```mermaid
flowchart TB
    subgraph APP["Application"]
        CTRL["Controllers<br/>@RequireScope · @AllowCallers"]
    end

    subgraph AUTH["Authorization"]
        GUARD["PeerIdentityGuard<br/>JwtAuthGuard"]
        REC["AccessRecorder<br/>audit + metrics"]
    end

    subgraph CRYPTO["Cryptography"]
        JWT["TokenVerifier<br/>ReplayCache"]
        MTLS["mTLS client/server<br/>SPIFFE checkServerIdentity"]
    end

    subgraph DATA["Key material"]
        PKI[(var/ca<br/>var/certs)]
        JWTS[(jwt-keys volume)]
        VAULT[(Vault<br/>sys/tools/random)]
    end

    CTRL --> GUARD
    GUARD --> REC
    GUARD --> JWT
    GUARD --> MTLS
    JWT --> JWTS
    MTLS --> PKI
    JWT --> VAULT

    classDef app fill:#667eea,stroke:#4c51bf,color:#fff
    classDef auth fill:#764ba2,stroke:#5a3673,color:#fff
    classDef crypto fill:#8b5cf6,stroke:#6d28d9,color:#fff
    classDef data fill:#f59e0b,stroke:#b45309,color:#000

    class CTRL app
    class GUARD,REC auth
    class JWT,MTLS crypto
    class PKI,JWTS,VAULT data
```

### The five networks

| Network | Members | Purpose | Enforcement |
|---|---|---|---|
| 🌐 `bastion-frontend` | `edge`, `rogue` | User-facing edge | Host-published `:8080` |
| 📦 `bastion-inventory` | `orders`, `inventory` | Order → stock | `DATA_BIND_ADDR` per-service |
| 💳 `bastion-payments` | `orders`, `payments` | Order → charge | `DATA_BIND_ADDR` per-service |
| 🔐 `bastion-vault` | `payments`, `vault` | Vault AppRole | Plain HTTP (dev) |
| ⚙️ `bastion-mgmt` | all + tools | `healthz`, metrics, JWKS | `internal: true` |

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔐 Identity & trust
- **SPIFFE IDs** on every cert (`spiffe://<domain>/services/<name>`)
- **mTLS everywhere** — including same-network hops
- **`checkServerIdentity`** verifies the callee's SPIFFE ID, not just its DNS name
- **Fail-closed** on missing/invalid CA, certs, JWT keys, or Vault token

</td>
<td width="50%" valign="top">

### 🎫 Tokens & replay
- **Ed25519 JWTs**, 5-min TTL
- **Per-service replay cache** — `jti` single-use
- **Audience-scoped** — a token for `payments` is rejected at `orders`
- **Fail-closed** on JWKS outage (503, not 401)
- **`aud`-scoped** — `aud` must contain the callee

</td>
</tr>
<tr>
<td valign="top">

### 🔄 Key rotation
- `make rotate-certs` — re-issues every service cert, CA untouched
- `make rotate-jwt` — new active key, previous stays published for TTL+60s
- `make vault-reauth` — re-issues the wrapped secret-id (F5)
- **Deterministic** — same seed + clock → byte-identical output

</td>
<td valign="top">

### 📊 Observability
- **4 Prometheus metrics** per service on `:909x/metrics`
- **Structured audit** to stdout + `var/audit/<svc>.log`
- **4 demos** that prove the security properties end-to-end
- **296 tests** across 37 suites

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

<img src="https://img.shields.io/badge/Docker-24%2B-2496ED?style=flat-square&logo=docker&logoColor=white" /> <img src="https://img.shields.io/badge/Docker_Compose-v2-2496ED?style=flat-square&logo=docker&logoColor=white" /> <img src="https://img.shields.io/badge/Node-20-339933?style=flat-square&logo=node.js&logoColor=white" /> <img src="https://img.shields.io/badge/pnpm-9-F69220?style=flat-square&logo=pnpm&logoColor=white" /> <img src="https://img.shields.io/badge/bash-4%2B-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white" />

### Start the stack

```bash
pnpm install
make up            # starts 5 containers, waits for all to be healthy
```

### Run the demos

```bash
make demo                 # happy path: login → order → 4 allow lines, one jwt_jti
make demo-rogue           # topology segmentation blocks the attacker
make demo-stolen-jwt      # three attack tokens are rejected
make demo-vault-rotation  # Vault key rotates, no key leak
```

### Stop

```bash
make down
```

---

## 🎬 Demos

| Demo | What it proves | Status |
|---|---|---|
| <img src="https://img.shields.io/badge/make_demo-22c55e?style=flat-square" /> | Login at edge → place order → audit shows 4 `allow` lines sharing one `jwt_jti` | ✅ Passing |
| <img src="https://img.shields.io/badge/make_demo--rogue-ef4444?style=flat-square" /> | Rogue cannot reach `payments` or `orders` (different networks). Topology is the first defense. | ✅ Passing |
| <img src="https://img.shields.io/badge/make_demo--stolen--jwt-f59e0b?style=flat-square" /> | Bad-audience token rejected. Tampered payload rejected. Replay rejected. | ✅ Passing |
| <img src="https://img.shields.io/badge/make_demo--vault--rotation-8b5cf6?style=flat-square" /> | Two orders 15s apart have different key fingerprints. No full key on disk or in logs. | ✅ Passing |

---

## 🔒 Security Model

### Seven NIST SP 800-207 tenets — all enforced

| # | Tenet | How Bastion enforces it |
|---|---|---|
| 1 | All services are resources | Each service, route, and Vault key has a distinct name; audit events carry `resource` |
| 2 | All communication is secured | mTLS on every internal hop, TLS on edge's client listener |
| 3 | Access is per-session | Fresh handshake each time, 5-min JWT with single-use `jti`, 10s Vault key rotation |
| 4 | Dynamic policy | `PeerIdentityGuard` + `JwtAuthGuard` + `@RequireScope` + route allowlist |
| 5 | Posture is monitored | Fail-closed on missing material; `rejected_expired` measured |
| 6 | Authn/authz strictly enforced | 401/403/503 before handler, `tlsClientError` audited |
| 7 | Collect state | Structured audit + 4 Prometheus metrics |

### Known gaps

<details>
<summary><b>Click to see what is <i>not</i> enforced and why</b></summary>

<br/>

- **Plaintext mgmt plane in Compose.** `internal: true` but no mTLS. k8s STRICT mTLS closes this.
- **Plaintext to Vault in Compose.** Dev Vault. Production would use TLS or Vault Agent.
- **JWKS on plaintext.** Anyone on `bastion-mgmt` can swap keys in Compose. Istio mTLS fixes it in k8s.
- **No session revocation.** A valid JWT is valid until `exp`.
- **No workload attestation.** Identity comes from files, not SPIRE/TPM.
- **Replay cache per-process.** Replicas don't share it.
- **Edge is issuer and first verifier.** A compromised edge can mint tokens.
- **k8s manifests are documented, not verified.** No cluster in CI.

Full analysis: [`docs/architecture.md`](docs/architecture.md).

</details>

---

## 📂 Project Structure

```
bastion/
├── apps/
│   ├── edge/           user login, JWT issuance, forward to orders
│   ├── orders/         orchestrates inventory + payments
│   ├── inventory/      in-memory stock ledger
│   └── payments/       Vault-derived API key, HMAC receipts
├── libs/bastion-common/
│   ├── mtls/           server-auth + mTLS option builders
│   ├── identity/       SPIFFE parsing, PeerIdentityGuard
│   ├── jwt/            claims, issuer, verifier, JWKS cache, replay cache
│   ├── audit/          structured events, trace IDs
│   ├── metrics/        4 Prometheus metrics
│   ├── auth/           JwtAuthGuard, @RequireScope
│   └── management/     /healthz, /metrics, /.well-known/jwks.json
├── scripts/            gen-certs, rotate-certs, mint-rogue-certs,
│                       rotate-jwt, forge-token, init, vault-bootstrap
├── demos/              4 end-to-end scripts
├── docker/             init image, rogue image
├── k8s/                Kubernetes + Istio manifests (documented target)
├── tests/              cross-service e2e test
└── var/                generated runtime material (gitignored)
```

---

## 🧪 Testing

<div align="center">

<img src="https://img.shields.io/badge/suites-37%2F37%20passing-22c55e?style=for-the-badge" />
<img src="https://img.shields.io/badge/tests-296%20passing-22c55e?style=for-the-badge" />
<img src="https://img.shields.io/badge/skipped-3%20(POSIX%20mode)-6b7280?style=for-the-badge" />

</div>

```bash
pnpm typecheck && pnpm lint && pnpm test
```

| Area | Coverage |
|---|---|
| 🔑 PKI | Cert issuance, key derivation, rotation, determinism |
| 🎫 JWT | Claims schema, expiry, audience, replay, tampering |
| 🔒 mTLS | Server identity, client identity, TLS errors |
| 🛡 Authorization | Peer checks, scope checks, 401/403/503 paths |
| 📊 Audit + metrics | Field redaction, control chars, sink failures |
| 🌐 e2e | Real mTLS + real JWTs + real JWKS, 4 services, 4 scenarios |

CI runs on Ubuntu 24.04 (`.github/workflows/ci.yml`). POSIX mode tests run there.

---

## 📚 Documentation

<div align="center">

| Document | What's inside |
|---|---|
| 📖 [README.md](README.md) | This file |
| 🏛 [docs/architecture.md](docs/architecture.md) | NIST tenets, trust boundaries, F1–F8 flaws, gaps |
| ☸️ [k8s/README.md](k8s/README.md) | Compose → Kubernetes mapping, apply order |
| 🤖 [.github/workflows/ci.yml](.github/workflows/ci.yml) | The GitHub Actions workflow |

</div>

---

## 🎨 Commands

<table>
<tr>
<td width="33%" valign="top">

### 🚀 Lifecycle
```bash
make up
make down
make restart
make clean
make logs
```

</td>
<td width="33%" valign="top">

### 🎬 Demos
```bash
make demo
make demo-rogue
make demo-stolen-jwt
make demo-vault-rotation
```

</td>
<td width="33%" valign="top">

### 🔄 Rotation
```bash
make rotate-certs
make rotate-jwt
make mint-rogue
make vault-reauth
```

</td>
</tr>
<tr>
<td valign="top">

### 📊 Observability
```bash
make metrics edge
make metrics orders
make audit-tail
```

</td>
<td valign="top">

### 🧪 Local CI
```bash
make typecheck
make lint
make test
make ci
```

</td>
<td valign="top">

### 🆘 Help
```bash
make help
```

</td>
</tr>
</table>

---

<div align="center">

<a href="https://github.com/Abdulgeni/bastion">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&height=120&section=footer&text=Built%20with%20%E2%9D%A4%EF%B8%8F%20for%20zero-trust&fontSize=24&fontColor=ffffff&animation=twinkling" alt="Bastion footer" />
</a>

**Bastion** · [architecture](docs/architecture.md) · [k8s](k8s/README.md) · [CI](.github/workflows/ci.yml)

</div>