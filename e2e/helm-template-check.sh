#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Renders the Helm chart with `helm template` in the configurations that matter and checks the output (item 5):
#   - the default (Redis sessions) requires redis.host and wires it;
#   - sessionStore=queue with the default token store renders WITHOUT redis.host, with no Redis env and no Redis
#     egress port;
#   - tokenStore=redis requires redis.host again, whatever the session store;
#   - an unknown store is refused.
# Needs only helm. Usage (repo root): e2e/helm-template-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
CHART=deploy/helm/helixiam
BASE=(--set config.idpBaseUrl=https://idp.example.test --set config.spBaseUrl=https://console.example.test
      --set database.host=postgres --set secrets.existingSecret=helix-secrets)
failures=0

fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "ok:   $*"; }

render() { helm template helixiam "$CHART" "${BASE[@]}" "$@" 2>&1; }

expect_render_error() { # $1 = description, $2 = expected message, rest = helm args
  local what=$1 message=$2 out
  shift 2
  if out=$(render "$@"); then
    fail "$what: rendered, expected an error"
  elif grep -qF "$message" <<<"$out"; then
    ok "$what: refused ($message)"
  else
    fail "$what: wrong error: $out"
  fi
}

expect_contains() { # $1 = description, $2 = rendered output, $3 = text
  if grep -qF -- "$3" <<<"$2"; then ok "$1"; else fail "$1: missing '$3'"; fi
}

expect_absent() {
  if grep -qF -- "$3" <<<"$2"; then fail "$1: unexpected '$3'"; else ok "$1"; fi
}

# 1. Default: Redis sessions.
expect_render_error "default without redis.host" "redis.host is required"
out=$(render --set redis.host=redis)
expect_contains "default: REDIS_HOST" "$out" 'REDIS_HOST: "redis"'
expect_contains "default: session store redis" "$out" 'HELIX_SESSION_STORE: "redis"'
expect_contains "default: redis egress port" "$out" "port: 6379"

# 2. Queue sessions, default (queue) token store: no Redis at all.
if out=$(render --set config.sessionStore=queue); then
  ok "queue sessions render without redis.host"
  expect_contains "queue: session store queue" "$out" 'HELIX_SESSION_STORE: "queue"'
  expect_contains "queue: token store queue" "$out" 'HELIX_TOKEN_STORE: "queue"'
  expect_absent "queue: no REDIS_HOST" "$out" "REDIS_HOST"
  expect_absent "queue: no REDIS_PORT" "$out" "REDIS_PORT"
  expect_absent "queue: no redis egress port" "$out" "port: 6379"
  expect_contains "queue: database egress port" "$out" "port: 5432"
else
  fail "queue sessions without redis.host: $out"
fi

# A redis.host that is set anyway is passed through (harmless, e.g. while switching stores).
out=$(render --set config.sessionStore=queue --set redis.host=redis)
expect_contains "queue + redis.host: REDIS_HOST passed" "$out" 'REDIS_HOST: "redis"'

# 3. Redis token store: Redis is required again.
expect_render_error "queue sessions + redis tokens without redis.host" "redis.host is required" \
  --set config.sessionStore=queue --set config.tokenStore=redis
out=$(render --set config.sessionStore=queue --set config.tokenStore=redis --set redis.host=redis)
expect_contains "redis tokens: HELIX_TOKEN_STORE" "$out" 'HELIX_TOKEN_STORE: "redis"'
expect_contains "redis tokens: REDIS_HOST" "$out" 'REDIS_HOST: "redis"'

# 4. Unknown stores are refused.
expect_render_error "unknown session store" "config.sessionStore must be redis or queue" --set config.sessionStore=jdbc
expect_render_error "unknown token store" "config.tokenStore must be queue or redis" --set config.tokenStore=memory \
  --set redis.host=redis

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "helm template checks passed"
