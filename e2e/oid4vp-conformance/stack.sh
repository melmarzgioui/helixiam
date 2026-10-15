#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Starts (up) or removes (down) the containers of a conformance run, all named oidf-* on the network oidf-net:
#   oidf-mongodb, oidf-suite-server, oidf-suite-nginx   the published OpenID Foundation conformance suite images
#   oidf-helix-pg                                       PostgreSQL for HelixIAM (127.0.0.1:$OIDF_PG_PORT)
#   oidf-helix-proxy                                    nginx terminating TLS for $OIDF_HOST:$OIDF_TLS_PORT and forwarding
#                                                       to HelixIAM on the host (host.docker.internal:$OIDF_HELIX_PORT); the
#                                                       network alias makes the suite reach it under the same name and port
# HelixIAM itself runs on the host (run-helix.sh). Usage: stack.sh up|proxy|down
set -euo pipefail
. "$(dirname "$0")/env.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
case "${1:-}" in
  up)
    docker network create oidf-net >/dev/null 2>&1 || true
    docker run -d --name oidf-mongodb --network oidf-net --network-alias mongodb mongo:6.0.13 >/dev/null
    docker run -d --name oidf-suite-server --network oidf-net --network-alias server \
      -e BASE_URL="https://localhost.emobix.co.uk:$OIDF_SUITE_PORT" -e BASE_MTLS_URL="https://localhost.emobix.co.uk:$((OIDF_SUITE_PORT + 1))" \
      -e MONGODB_HOST=mongodb -e SPRING_PROFILES_ACTIVE=dev \
      -e OIDC_GOOGLE_CLIENTID=unused -e OIDC_GOOGLE_SECRET=unused -e OIDC_GITLAB_CLIENTID=unused -e OIDC_GITLAB_SECRET=unused \
      "registry.gitlab.com/openid/conformance-suite:$OIDF_SUITE_IMAGE_TAG" >/dev/null
    docker run -d --name oidf-suite-nginx --network oidf-net -p "127.0.0.1:$OIDF_SUITE_PORT:8443" \
      "registry.gitlab.com/openid/conformance-suite/nginx:$OIDF_SUITE_IMAGE_TAG" >/dev/null
    docker run -d --name oidf-helix-pg -e POSTGRES_DB=helixiam -e POSTGRES_USER=helix -e POSTGRES_PASSWORD=helix \
      -p "127.0.0.1:$OIDF_PG_PORT:5432" postgres:16-alpine >/dev/null
    for _ in $(seq 1 60); do curl -fsk "https://localhost:$OIDF_SUITE_PORT/api/server" >/dev/null 2>&1 && break; sleep 2; done
    curl -fsk "https://localhost:$OIDF_SUITE_PORT/api/server"; echo
    ;;
  proxy)  # after pki.sh: the TLS proxy needs the certificate
    mkdir -p "$OIDF_WORK/proxy"
    cp "$OIDF_WORK/pki/tls-fullchain.pem" "$OIDF_WORK/pki/tls.key" "$OIDF_WORK/proxy/"
    sed -e "s/__HOST__/$OIDF_HOST/g" -e "s/__TLS_PORT__/$OIDF_TLS_PORT/g" -e "s/__HELIX_PORT__/$OIDF_HELIX_PORT/g" \
      "$HERE/helix-proxy.conf" > "$OIDF_WORK/proxy/default.conf"
    docker run -d --name oidf-helix-proxy --network oidf-net --network-alias "$OIDF_HOST" \
      -p "127.0.0.1:$OIDF_TLS_PORT:$OIDF_TLS_PORT" -v "$OIDF_WORK/proxy/default.conf:/etc/nginx/conf.d/default.conf:ro" \
      -v "$OIDF_WORK/proxy:/etc/nginx/tls:ro" nginx:alpine >/dev/null
    ;;
  down)
    docker rm -f oidf-helix-proxy oidf-helix-pg oidf-suite-nginx oidf-suite-server oidf-mongodb >/dev/null 2>&1 || true
    docker network rm oidf-net >/dev/null 2>&1 || true
    ;;
  *) echo "usage: $0 up|proxy|down" >&2; exit 2 ;;
esac
