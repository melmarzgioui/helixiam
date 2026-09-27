#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Release gate: boot the Helm chart's DEFAULT configuration on a fresh k3d cluster + empty PostgreSQL, wait
# for readiness, then run the scripted Monthfold end-to-end check and validate every token with Go jwx.
# Only the values the chart REQUIRES are set (image, URLs, database/redis hosts, the secret name).
#
# Usage (repo root): e2e/monthfold/k3d-helm.sh            # builds the image from helix-iam-server/
#                    KEEP=1 e2e/monthfold/k3d-helm.sh     # leave the cluster running afterwards
#                    NO_REDIS=1 e2e/monthfold/k3d-helm.sh # item 5: config.sessionStore=queue, no redis.host and no
#                                                         # Redis in the cluster; sessions and tokens in PostgreSQL
#                    SKIP_BUILD=1 ...                     # use an already built $IMAGE
set -euo pipefail
cd "$(dirname "$0")/../.."
CLUSTER=${CLUSTER:-helix-e2e}
IMAGE=${IMAGE:-helixiam/helix-iam-server:e2e}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-Helm-Admin-Passw0rd!}
PORT=${PORT:-18080}
kc() { kubectl --context "k3d-$CLUSTER" -n helix "$@"; }

if [ -z "${SKIP_BUILD:-}" ]; then
  docker build -q -t "$IMAGE" -f helix-iam-server/Dockerfile helix-iam-server
fi
k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
k3d cluster create "$CLUSTER" --no-lb --wait
k3d image import "$IMAGE" -c "$CLUSTER"
kubectl --context "k3d-$CLUSTER" create namespace helix
kc apply -f e2e/monthfold/k8s-postgres-redis.yaml
if [ -n "${NO_REDIS:-}" ]; then
  kc delete deployment/redis service/redis --wait=true # nothing in the cluster answers on redis:6379
fi
kc create secret generic helix-secrets --from-literal=db-username=helixiam --from-literal=db-password=helixiam-db-pw \
  --from-literal=db-encryption=00112233445566778899aabbccddeeff --from-literal=admin-password="$ADMIN_PASSWORD"
kc rollout status deploy/postgres --timeout=180s
if [ -n "${NO_REDIS:-}" ]; then
  STORE_ARGS=(--set config.sessionStore=queue)
else
  kc rollout status deploy/redis --timeout=180s
  STORE_ARGS=(--set redis.host=redis)
fi

helm --kube-context "k3d-$CLUSTER" -n helix install helixiam deploy/helm/helixiam \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE##*:}" \
  --set config.idpBaseUrl=https://idp.example.test --set config.spBaseUrl=https://console.example.test \
  --set database.host=postgres --set secrets.existingSecret=helix-secrets "${STORE_ARGS[@]}"
kc rollout status deploy/helixiam --timeout=420s
kc exec deploy/helixiam -- curl -fsS http://127.0.0.1:8080/actuator/health/readiness; echo
if [ -n "${NO_REDIS:-}" ]; then
  kc exec deploy/helixiam -- curl -fsS http://127.0.0.1:8080/actuator/health; echo
  if kc exec deploy/helixiam -- env | grep -q '^REDIS_HOST='; then
    echo "REDIS_HOST is set in the queue-store release" >&2
    exit 1
  fi
  kc get deploy,svc redis >/dev/null 2>&1 && { echo "Redis is running in the NO_REDIS cluster" >&2; exit 1; }
  echo "no Redis: session store $(kc exec deploy/helixiam -- printenv HELIX_SESSION_STORE)," \
    "token store $(kc exec deploy/helixiam -- printenv HELIX_TOKEN_STORE)"
fi
kc exec deploy/postgres -- psql -U helixiam -d helixiam -tAc \
  "select 'flyway V' || max(version::int) || ', all successful: ' || bool_and(success) from flyway_schema_history"

kc port-forward svc/helixiam "$PORT:8080" >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null; [ -n "${KEEP:-}" ] || k3d cluster delete "$CLUSTER" >/dev/null 2>&1' EXIT
for _ in $(seq 1 30); do curl -fsS -o /dev/null "http://localhost:$PORT/actuator/health" && break; sleep 1; done

rm -rf e2e/monthfold/out
python3 e2e/monthfold/run.py --base "http://localhost:$PORT" --admin-password "$ADMIN_PASSWORD"
(cd e2e/monthfold/jwxcheck && go run . ../out/tokens.json)
