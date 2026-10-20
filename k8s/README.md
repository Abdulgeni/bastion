# Bastion on Kubernetes

This directory maps the Compose topology to Kubernetes + Istio. **None of it
is tested on a cluster** - Compose is the reference implementation and this
is the documented target.

## Files

| File | Mirrors in Compose |
|---|---|
| `namespace.yaml` | `bastion-*` networks (istio-injection enabled) |
| `pvc.yaml` | `./var` bind mount |
| `init-job.yaml` | `bastion-init` (Job, runs once per bootstrap) |
| `services/edge.yaml` | `edge` Deployment + Service |
| `services/orders.yaml` | `orders` Deployment + Service |
| `services/inventory.yaml` | `inventory` Deployment + Service |
| `services/payments.yaml` | `payments` Deployment + Service |
| `peer-authentication.yaml` | Every data/mgmt hop is mTLS (STRICT) |
| `authorization-policy.yaml` | The five-network call graph as Istio ALLOW rules |
| `network-policy.yaml` | The same call graph as NetworkPolicy (defense in depth) |
| `vault-agent/configmap.yaml` | Documents the production Vault pattern |

## What is not here

- **Vault itself.** Compose uses `hashicorp/vault:1.17.2 -dev`, a demo
  convenience. In k8s, Vault is installed separately (Helm chart), and the
  payments ServiceAccount authenticates via the Kubernetes auth method.
- **A Job for `bastion-vault-bootstrap`.** The Compose init chain has three
  stages (`bastion-init` -> `vault` -> `bastion-vault-bootstrap`). Here only
  `bastion-init` is a Job; Vault bootstrap is assumed to run against the
  real Vault install with proper AppRole policy.
- **Ingress/Gateway for the edge data port.** Compose publishes `:8080` to
  the host; k8s needs a Gateway or Ingress to do the same. Cluster-specific
  and out of scope for these manifests.

## Differences from Compose

- **Management plane is mTLS-protected too.** In Compose the mgmt network is
  `internal: true` but plaintext. STRICT mTLS covers it here, which closes
  the gap noted in Step 1 (assumption 5 / F2 gap).
- **`bastion-init` runs as a Job, not a compose service.** Same
  `scripts/init.ts`, same `BASTION_VAR_DIR=/var/bastion`, different invocation.
- **Vault Agent injection is the target**, not root-token files. Current
  `payments` code still reads the file-based credentials from `/var/bastion`.
  Moving to Vault Agent is a one-method change in `KeyHolder`.

## Applying

These manifests assume:

- A Kubernetes 1.28+ cluster with Istio installed
- A `bastion-var` PVC available (see `pvc.yaml`)
- Images `bastion-edge`, `bastion-orders`, `bastion-inventory`,
  `bastion-payments`, `bastion-init` pushed to a registry the cluster can
  pull from (tag `:dev` used in the manifests)
- Vault installed and reachable at `vault.vault.svc:8200` with a `payments`
  AppRole (or Kubernetes auth role)

Apply in this order:

1. `kubectl apply -f k8s/namespace.yaml`
2. `kubectl apply -f k8s/pvc.yaml`
3. `kubectl apply -f k8s/init-job.yaml`
4. `kubectl wait --for=condition=complete -n bastion job/bastion-init`
5. `kubectl apply -f k8s/services/`
6. `kubectl apply -f k8s/peer-authentication.yaml`
7. `kubectl apply -f k8s/authorization-policy.yaml`
8. `kubectl apply -f k8s/network-policy.yaml`
