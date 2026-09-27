#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Renders the Helm chart with `helm template` in the configurations that matter and checks the output (item 5):
#   - the default (Redis sessions) requires redis.host and wires it;
#   - sessionStore=queue with the default token store renders WITHOUT redis.host, with no Redis env and no Redis
#     egress port;
#   - tokenStore=redis requires redis.host again, whatever the session store;
#   - an unknown store is refused;
#   - the global email settings are optional; their secrets are mounted as files, never env values;
#   - the email retry, rate-cap and code-lifetime values are passed through when set (0 and false included).
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

# 5. Global email: nothing by default; Cloudflare / SMTPS settings with secrets mounted as files.
out=$(render --set redis.host=redis)
expect_absent "email: nothing by default" "$out" "HELIX_NOTIFICATION_"
expect_absent "email: no secret volume by default" "$out" "email-secrets"
out=$(render --set redis.host=redis --set email.driver=cloudflare --set email.fromAddress=no-reply@example.test \
  --set email.cloudflare.accountId=acct --set email.cloudflare.apiTokenKey=cf-token \
  --set email.smtp.host=smtp.example.test --set email.smtp.tlsMode=IMPLICIT --set-string email.smtp.port=465 \
  --set email.smtp.passwordKey=smtp-password)
expect_contains "email: driver" "$out" 'HELIX_NOTIFICATION_EMAIL_DRIVER: "cloudflare"'
expect_contains "email: account id" "$out" 'HELIX_NOTIFICATION_CLOUDFLARE_ACCOUNT_ID: "acct"'
expect_contains "email: token file" "$out" 'HELIX_NOTIFICATION_CLOUDFLARE_API_TOKEN_FILE: "/etc/helixiam/email/cloudflare-api-token"'
expect_contains "email: smtp tls mode" "$out" 'HELIX_NOTIFICATION_SMTP_TLS_MODE: "IMPLICIT"'
expect_contains "email: smtp password file" "$out" 'HELIX_NOTIFICATION_SMTP_PASSWORD_FILE: "/etc/helixiam/email/smtp-password"'
expect_contains "email: token mounted" "$out" "path: cloudflare-api-token"
expect_contains "email: password mounted" "$out" "path: smtp-password"
expect_absent "email: no token env value" "$out" "HELIX_NOTIFICATION_CLOUDFLARE_API_TOKEN:"
expect_render_error "cloudflare without account id" "email.cloudflare.accountId is required" --set redis.host=redis \
  --set email.driver=cloudflare --set email.cloudflare.apiTokenKey=cf-token
expect_render_error "cloudflare without token" "email.cloudflare.apiTokenKey is required" --set redis.host=redis \
  --set email.driver=cloudflare --set email.cloudflare.accountId=acct

# 6. Email retries, rate caps and code lifetimes: nothing by default (checked above); each value when set, 0 and false
#    included (a cap of 0 switches it off).
out=$(render --set redis.host=redis --set email.retry.enabled=false --set-string 'email.retry.delays=30s\,2m' \
  --set email.retry.maxAge=45m --set email.retry.jitter=0.1 --set email.retry.pollInterval=10s \
  --set email.retry.batchSize=50 --set email.retry.lease=3m --set email.rateLimit.realmPerMinute=0 \
  --set email.rateLimit.globalPerMinute=900 --set email.codes.resetPasswordTtl=30m --set email.codes.signupTtl=12h)
expect_contains "email: retry enabled" "$out" 'HELIX_NOTIFICATION_EMAIL_RETRY_ENABLED: "false"'
expect_contains "email: retry delays" "$out" 'HELIX_NOTIFICATION_EMAIL_RETRY_DELAYS: "30s,2m"'
expect_contains "email: retry max age" "$out" 'HELIX_NOTIFICATION_EMAIL_RETRY_MAX_AGE: "45m"'
expect_contains "email: retry jitter" "$out" 'HELIX_NOTIFICATION_EMAIL_RETRY_JITTER: "0.1"'
expect_contains "email: retry poll interval" "$out" 'HELIX_NOTIFICATION_EMAIL_RETRY_POLL_INTERVAL: "10s"'
expect_contains "email: retry batch size" "$out" 'HELIX_NOTIFICATION_EMAIL_RETRY_BATCH_SIZE: "50"'
expect_contains "email: retry lease" "$out" 'HELIX_NOTIFICATION_EMAIL_RETRY_LEASE: "3m"'
expect_contains "email: realm cap 0 (off)" "$out" 'HELIX_NOTIFICATION_EMAIL_RATE_LIMIT_REALM_PER_MINUTE: "0"'
expect_contains "email: global cap" "$out" 'HELIX_NOTIFICATION_EMAIL_RATE_LIMIT_GLOBAL_PER_MINUTE: "900"'
expect_contains "email: reset code ttl" "$out" 'HELIX_NOTIFICATION_RESET_PASSWORD_CODE_TTL: "30m"'
expect_contains "email: signup code ttl" "$out" 'HELIX_NOTIFICATION_SIGNUP_CODE_TTL: "12h"'

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "helm template checks passed"
