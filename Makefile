# Bastion developer workflow.
#
# Targets that matter for a fresh run:
#   make up          start the stack (waits for all four services healthy)
#   make demo        happy-path end-to-end demo
#   make down        stop and remove containers (keeps var/)
#
# Targets that need extra profiles:
#   make demo-rogue          requires --profile rogue
#   make metrics <svc>       requires --profile tools
#
# Targets that operate on files under var/:
#   make rotate-certs / rotate-jwt / mint-rogue / vault-reauth
#
# See docs/architecture.md and Step 1's demos table for what each expects.

SHELL := /bin/bash
COMPOSE := docker compose
SERVICES := edge orders inventory payments
EDGE_DATA_HOST_PORT ?= 8080

.PHONY: help up down restart clean logs \
        demo demo-rogue demo-stolen-jwt demo-vault-rotation \
        rotate-certs rotate-jwt mint-rogue vault-reauth \
        metrics audit-tail \
        test lint typecheck ci

help: ## Print this help.
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------
# Lifecycle
# ------------------------------------------------------------------
up: ## Start the stack (init → vault → bootstrap → 4 services), wait healthy.
	$(COMPOSE) up -d --wait
	@echo
	@echo "edge data: http://localhost:$(EDGE_DATA_HOST_PORT)"
	@echo "audit:     tail -f var/audit/<service>.log"
	@echo "metrics:   make metrics edge"

down: ## Stop and remove containers (keeps var/).
	$(COMPOSE) --profile tools --profile rogue down

restart: ## Restart the four data-plane services (does not rerun init/vault).
	$(COMPOSE) restart edge orders inventory payments

clean: ## Down + remove containers, networks, and named volumes. Keeps var/.
	$(COMPOSE) --profile tools --profile rogue down --remove-orphans
	@echo "var/ preserved; delete it manually if you want a fresh CA and keys."

logs: ## Tail logs from all running services.
	$(COMPOSE) logs -f --tail=50

# ------------------------------------------------------------------
# Demos (scripts land in Step 8; these targets are wired now)
# ------------------------------------------------------------------
demo: ## Happy-path demo: login → order → all four services allow.
	@bash demos/demo.sh

demo-rogue: ## Rogue demo: start the rogue profile, prove it is denied.
	$(COMPOSE) --profile rogue up -d rogue
	@bash demos/demo-rogue.sh

demo-stolen-jwt: ## Three stolen-token scenarios: bad_aud, bad_sig, replayed.
	@bash demos/demo-stolen-jwt.sh

demo-vault-rotation: ## Two orders ~15s apart; fingerprints must differ.
	@bash demos/demo-vault-rotation.sh

# ------------------------------------------------------------------
# Key rotation (operate on files under var/, not on the running stack)
# ------------------------------------------------------------------
rotate-certs: ## Re-issue every service cert (CA unchanged). Restart to apply.
	pnpm rotate-certs

rotate-jwt: ## Rotate edge's JWT signing key (previous stays published).
	pnpm rotate-jwt

mint-rogue: ## Create the two rogue certs under var/rogue/. Idempotent.
	pnpm mint-rogue-certs

vault-reauth: ## Re-issue the wrapped secret-id after a lone payments restart.
	docker compose run --rm --entrypoint /bin/bash bastion-vault-bootstrap /repo/scripts/vault-reauth.sh

# ------------------------------------------------------------------
# Metrics + audit
# ------------------------------------------------------------------
metrics: ## Read /metrics from one service (default edge): make metrics edge
	@svc=$${1:-edge}; \
	 mgmt=$$(case $$svc in edge) echo 9090;; orders) echo 9091;; inventory) echo 9092;; payments) echo 9093;; *) echo "unknown service: $$svc" >&2; exit 1;; esac); \
	 $(COMPOSE) --profile tools run --rm tools curl -fsS http://$$svc:$$mgmt/metrics

audit-tail: ## Tail the audit logs of all four services.
	@tail -F var/audit/edge.log var/audit/orders.log var/audit/inventory.log var/audit/payments.log

# ------------------------------------------------------------------
# Local CI
# ------------------------------------------------------------------
test: ## Run the Jest suite.
	pnpm test

lint: ## Lint everything.
	pnpm lint

typecheck: ## TypeScript check.
	pnpm typecheck

ci: typecheck lint test ## All checks. This is what Step 9's GitHub Action runs.
	@echo "ci: ok"
