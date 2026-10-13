#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Checks deploy/scripts/redis-delete-keys.sh (the rollback step in docs/UPGRADING.md) against real Redis servers in
# Docker: plain + requirepass, an ACL user, TLS, and a 3-master cluster. Each gets 1200 matching keys and 5 others; the
# script must delete exactly the matching ones. Needs only Docker. Usage (repo root): e2e/redis-delete-keys-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=redis:7-alpine
NET=helix-redis-check
WORK=$(mktemp -d)
cleanup() { docker rm -f rdk-plain rdk-acl rdk-tls rdk-cluster >/dev/null 2>&1 || true
            docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
cleanup; WORK=$(mktemp -d)
docker network create "$NET" >/dev/null
failures=0

# Runs the script (and redis-cli) in a client container on the network: run <env...> -- <args>
run() {
  local envs=()
  while [ "$1" != "--" ]; do envs+=(-e "$1"); shift; done; shift
  docker run --rm --network "$NET" "${envs[@]}" -v "$PWD/deploy/scripts:/scripts:ro" -v "$WORK:/work:ro" "$IMG" "$@"
}
seed() { # seed <host> <port> <redis-cli connection args...>: 1200 matching keys, 5 others
  local host=$1 port=$2; shift 2
  run X=1 -- sh -c "for i in \$(seq 1 1200); do echo \"SET spring:session:sessions:\$i v\"; done;
    for i in 1 2 3 4 5; do echo \"SET helix:keep:\$i v\"; done" > "$WORK/seed.txt"
  run X=1 -- sh -c "redis-cli -h $host -p $port $* < /work/seed.txt > /dev/null"
}
count() { # count <host> <port> <pattern> <args...>
  local host=$1 port=$2 pattern=$3; shift 3
  run X=1 -- sh -c "redis-cli -h $host -p $port $* --scan --pattern '$pattern' | wc -l" | tr -d ' '
}
check() { # check <name> <expected-line> <actual>
  if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1: expected '$2', got '$3'" >&2; failures=$((failures + 1)); fi
}

# 1. Plain server with requirepass.
docker run -d --name rdk-plain --network "$NET" "$IMG" redis-server --requirepass s3cret >/dev/null
sleep 1
seed rdk-plain 6379 --no-auth-warning -a s3cret
out=$(run REDIS_HOST=rdk-plain REDIS_PASSWORD=s3cret -- sh /scripts/redis-delete-keys.sh 'spring:session:*')
check "requirepass: deleted" "deleted 1200 key(s) matching spring:session:*" "$out"
check "requirepass: others kept" 5 "$(count rdk-plain 6379 'helix:keep:*' --no-auth-warning -a s3cret)"
check "requirepass: none left" 0 "$(count rdk-plain 6379 'spring:session:*' --no-auth-warning -a s3cret)"

# 2. ACL user.
docker run -d --name rdk-acl --network "$NET" "$IMG" redis-server \
  --user default off --user helix on '>u-s3cret' '~*' '&*' '+@all' >/dev/null
sleep 1
seed rdk-acl 6379 --no-auth-warning --user helix --pass u-s3cret
out=$(run REDIS_HOST=rdk-acl REDIS_USER=helix REDIS_PASSWORD=u-s3cret -- sh /scripts/redis-delete-keys.sh 'spring:session:*')
check "acl user: deleted" "deleted 1200 key(s) matching spring:session:*" "$out"
check "acl user: others kept" 5 "$(count rdk-acl 6379 'helix:keep:*' --no-auth-warning --user helix --pass u-s3cret)"

# 3. TLS (server certificate from a throwaway CA; no client certificate required).
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -days 1 -subj "/CN=helix-check-ca" \
  2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/server.key" -out "$WORK/server.csr" -subj "/CN=rdk-tls" 2>/dev/null
printf 'subjectAltName=DNS:rdk-tls\n' > "$WORK/san.ext"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial -days 1 \
  -extfile "$WORK/san.ext" -out "$WORK/server.crt" 2>/dev/null
chmod 644 "$WORK"/*
docker run -d --name rdk-tls --network "$NET" -v "$WORK:/tls:ro" "$IMG" redis-server --port 0 --tls-port 6379 \
  --tls-cert-file /tls/server.crt --tls-key-file /tls/server.key --tls-ca-cert-file /tls/ca.crt \
  --tls-auth-clients no --requirepass t-s3cret >/dev/null
sleep 1
TLSARGS="--tls --cacert /work/ca.crt --no-auth-warning -a t-s3cret"
seed rdk-tls 6379 $TLSARGS
out=$(run REDIS_HOST=rdk-tls REDIS_TLS=1 REDIS_CACERT=/work/ca.crt REDIS_PASSWORD=t-s3cret -- \
  sh /scripts/redis-delete-keys.sh 'spring:session:*')
check "tls: deleted" "deleted 1200 key(s) matching spring:session:*" "$out"
check "tls: others kept" 5 "$(count rdk-tls 6379 'helix:keep:*' $TLSARGS)"

# 4. Cluster: three masters in one container (ports 7000-7002), keys spread over all of them.
docker run -d --name rdk-cluster --network "$NET" "$IMG" sh -c '
  for p in 7000 7001 7002; do redis-server --port $p --cluster-enabled yes --cluster-config-file /tmp/n$p.conf \
    --cluster-announce-hostname rdk-cluster --cluster-preferred-endpoint-type hostname --daemonize yes; done
  sleep 1; yes yes | redis-cli --cluster create rdk-cluster:7000 rdk-cluster:7001 rdk-cluster:7002 >/dev/null
  tail -f /dev/null' >/dev/null
sleep 6
seed rdk-cluster 7000 -c
per_node=$(for p in 7000 7001 7002; do count rdk-cluster $p 'spring:session:*'; done | tr '\n' ' ')
echo "      cluster: matching keys per master before: $per_node"
out=$(run REDIS_HOST=rdk-cluster REDIS_PORT=7000 REDIS_CLUSTER=1 -- sh /scripts/redis-delete-keys.sh 'spring:session:*')
check "cluster: deleted on every master" "deleted 1200 key(s) matching spring:session:*" "$out"
left=0; kept=0
for p in 7000 7001 7002; do
  left=$((left + $(count rdk-cluster $p 'spring:session:*'))); kept=$((kept + $(count rdk-cluster $p 'helix:keep:*')))
done
check "cluster: none left" 0 "$left"
check "cluster: others kept" 5 "$kept"

if [ "$failures" -gt 0 ]; then echo "$failures check(s) failed" >&2; exit 1; fi
echo "redis-delete-keys checks passed"
