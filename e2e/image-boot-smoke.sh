#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Image boot smoke test (item C1): build the server image natively for THIS machine's architecture, start it the
# way the Helm chart's defaults do (the chart's ConfigMap + Secret env, non-root, read-only root FS with a /tmp
# tmpfs, all capabilities dropped) against an empty PostgreSQL and a Redis, and wait for
# /actuator/health/readiness to report UP. Used by CI on ubuntu-latest (amd64) and ubuntu-24.04-arm (arm64), and
# runnable locally (e.g. an arm64 Mac).
#
# Usage (repo root): e2e/image-boot-smoke.sh
#   IMAGE=helixiam/helix-iam-server:smoke   image tag to build/run
#   SKIP_BUILD=1                            run an already built $IMAGE
#   TIMEOUT=300                             seconds to wait for readiness
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE=${IMAGE:-helixiam/helix-iam-server:smoke}
TIMEOUT=${TIMEOUT:-300}
RUN=helix-smoke-$$
NET=$RUN-net
PORT=${PORT:-18088}

cleanup() {
  docker rm -f "$RUN-server" "$RUN-postgres" "$RUN-redis" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

case "$(uname -m)" in
  x86_64 | amd64) EXPECTED_ARCH=amd64 ;;
  aarch64 | arm64) EXPECTED_ARCH=arm64 ;;
  *) EXPECTED_ARCH=$(uname -m) ;;
esac

if [ -z "${SKIP_BUILD:-}" ]; then
  docker build -t "$IMAGE" -f helix-iam-server/Dockerfile helix-iam-server
fi
IMAGE_ARCH=$(docker image inspect -f '{{.Architecture}}' "$IMAGE")
echo "image $IMAGE: linux/$IMAGE_ARCH (host: $(uname -m))"
if [ "$IMAGE_ARCH" != "$EXPECTED_ARCH" ]; then
  echo "expected a native linux/$EXPECTED_ARCH image, got linux/$IMAGE_ARCH" >&2
  exit 1
fi

docker network create "$NET" >/dev/null
docker run -d --name "$RUN-postgres" --network "$NET" --network-alias postgres \
  -e POSTGRES_DB=helixiam -e POSTGRES_USER=helixiam -e POSTGRES_PASSWORD=helixiam-db-pw postgres:16-alpine >/dev/null
docker run -d --name "$RUN-redis" --network "$NET" --network-alias redis redis:7-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$RUN-postgres" pg_isready -U helixiam -d helixiam >/dev/null 2>&1 && break
  sleep 1
done

# The env the chart renders with only its required values set (see deploy/helm/helixiam/templates/configmap.yaml,
# deployment.yaml and e2e/monthfold/k3d-helm.sh), plus the container security context of values.yaml.
docker run -d --name "$RUN-server" --network "$NET" -p "127.0.0.1:$PORT:8080" \
  --read-only --tmpfs /tmp:rw,size=256m --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
  -e SERVER_PORT=8080 \
  -e DB_HOST=postgres -e DB_RO_HOST=postgres -e DB_PORT=5432 -e DB_NAME=helixiam \
  -e REDIS_HOST=redis -e REDIS_PORT=6379 \
  -e IDP_BASE_URL=https://idp.example.test -e SP_BASE_URL=https://console.example.test \
  -e HELIX_SAML_IDP_ENTITY_ID=https://idp.example.test/realms/master -e HELIX_SAML_IDP_ENABLED=true \
  -e HELIX_SESSION_STORE=redis -e USER_REGISTRATION_ENABLED=false -e HELIX_ACTUATOR_PROMETHEUS_ANONYMOUS=false \
  -e HELIX_COOKIE_SECURE=true -e HELIX_MIGRATIONS_ENABLED=true -e HELIX_SQL_INIT_MODE=never \
  -e HELIX_ADMIN_USERNAME=admin -e HELIX_ADMIN_PASSWORD='Smoke-Admin-Passw0rd!' \
  -e DB_USERNAME=helixiam -e DB_PASSWORD=helixiam-db-pw -e DB_ENCRYPTION=00112233445566778899aabbccddeeff \
  "$IMAGE" >/dev/null

start=$(date +%s)
status=""
while [ $(( $(date +%s) - start )) -lt "$TIMEOUT" ]; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$RUN-server")" != "true" ]; then
    echo "server container exited" >&2
    break
  fi
  status=$(curl -fsS "http://127.0.0.1:$PORT/actuator/health/readiness" 2>/dev/null || true)
  case "$status" in
    *'"status":"UP"'*) break ;;
  esac
  sleep 3
done
elapsed=$(( $(date +%s) - start ))

case "$status" in
  *'"status":"UP"'*)
    echo "readiness UP after ${elapsed}s on linux/$IMAGE_ARCH: $status"
    echo "liveness: $(curl -fsS "http://127.0.0.1:$PORT/actuator/health/liveness")"
    echo "flyway: $(docker exec "$RUN-postgres" psql -U helixiam -d helixiam -tAc \
      "select 'V' || max(version::int) || ', all successful: ' || bool_and(success) from flyway_schema_history")"
    ;;
  *)
    echo "readiness NOT UP after ${elapsed}s (last: ${status:-no response})" >&2
    docker logs --tail 200 "$RUN-server" >&2 || true
    exit 1
    ;;
esac
