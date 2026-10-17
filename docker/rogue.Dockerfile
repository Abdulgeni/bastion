# syntax=docker/dockerfile:1.7
# The rogue workload: a plain Node + curl image with no bastion-common code.
# It is only used by `demo-rogue.sh` to attempt calls to inventory/payments
# with the two attacker certs in var/rogue/.
FROM node:20-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
CMD ["sleep", "infinity"]
