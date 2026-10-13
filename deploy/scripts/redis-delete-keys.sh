#!/usr/bin/env sh
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Deletes the Redis keys matching a pattern, for the rollback in docs/UPGRADING.md:
#   deploy/scripts/redis-delete-keys.sh 'spring:session:*'   # HTTP sessions (the default session store)
#   deploy/scripts/redis-delete-keys.sh 'helix:authz:*'      # tokens, with HELIX_TOKEN_STORE=redis
# Needs redis-cli (6+). Connection settings, all optional:
#   REDIS_HOST (localhost), REDIS_PORT (6379)
#   REDIS_USER + REDIS_PASSWORD (ACL user) or REDIS_PASSWORD alone (requirepass); passed via REDISCLI_AUTH / --user,
#     never on the command line
#   REDIS_TLS=1 with REDIS_CACERT (CA file), optionally REDIS_CERT + REDIS_KEY (client certificate)
#   REDIS_CLUSTER=1: every master is scanned (a SCAN on one node only sees that node's keys)
# Prints the number of keys deleted. Uses SCAN (never KEYS) and UNLINK (in batches of 500; one key at a time on a
# cluster, where a multi-key command must stay within one hash slot).
set -eu
PATTERN=${1:?usage: redis-delete-keys.sh <pattern>}
HOST=${REDIS_HOST:-localhost}
PORT=${REDIS_PORT:-6379}

cli() { # cli <host> <port> <redis-cli args...>
  h=$1; p=$2; shift 2
  set -- -h "$h" -p "$p" "$@"
  [ -n "${REDIS_USER:-}" ] && set -- --user "$REDIS_USER" "$@"
  if [ -n "${REDIS_TLS:-}" ]; then
    set -- --tls "$@"
    [ -n "${REDIS_CACERT:-}" ] && set -- --cacert "$REDIS_CACERT" "$@"
    [ -n "${REDIS_CERT:-}" ] && set -- --cert "$REDIS_CERT" --key "${REDIS_KEY:?REDIS_KEY is required with REDIS_CERT}" "$@"
  fi
  if [ -n "${REDIS_PASSWORD:-}" ]; then
    REDISCLI_AUTH=$REDIS_PASSWORD redis-cli --no-auth-warning "$@"
  else
    redis-cli "$@"
  fi
}

nodes() {
  if [ -n "${REDIS_CLUSTER:-}" ]; then
    # "<id> <ip:port@cport[,hostname]> <flags> ...": the masters' addresses.
    cli "$HOST" "$PORT" cluster nodes | awk '$3 ~ /master/ && $3 !~ /fail/ {split($2, a, "@"); print a[1]}'
  else
    echo "$HOST:$PORT"
  fi
}

# Cluster: a multi-key UNLINK must stay within one hash slot, so one key per command there.
BATCH=500
[ -n "${REDIS_CLUSTER:-}" ] && BATCH=1
export REDIS_USER REDIS_PASSWORD REDIS_TLS REDIS_CACERT REDIS_CERT REDIS_KEY 2>/dev/null || true
KEYS=$(mktemp)
trap 'rm -f "$KEYS"' EXIT
total=0
for node in $(nodes); do
  h=${node%:*}; p=${node##*:}
  # The whole key list first (SCAN may repeat a key), then the deletes: deleting while SCAN iterates can make it miss
  # keys.
  cli "$h" "$p" --scan --pattern "$PATTERN" | sort -u > "$KEYS"
  n=$(xargs -r -n "$BATCH" sh -c '
      h=$0; p=$1; shift 1 # $0 = host, $1 = port, the rest = keys
      set -- -h "$h" -p "$p" unlink "$@"
      [ -n "${REDIS_USER:-}" ] && set -- --user "$REDIS_USER" "$@"
      if [ -n "${REDIS_TLS:-}" ]; then
        set -- --tls "$@"
        [ -n "${REDIS_CACERT:-}" ] && set -- --cacert "$REDIS_CACERT" "$@"
        [ -n "${REDIS_CERT:-}" ] && set -- --cert "$REDIS_CERT" --key "$REDIS_KEY" "$@"
      fi
      if [ -n "${REDIS_PASSWORD:-}" ]; then
        REDISCLI_AUTH=$REDIS_PASSWORD redis-cli --no-auth-warning "$@"
      else
        redis-cli "$@"
      fi' "$h" "$p" < "$KEYS" | awk '{s += $1} END {print s + 0}')
  total=$((total + n))
done
echo "deleted $total key(s) matching $PATTERN"
