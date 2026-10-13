#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Upgrade-path gate (docs/UPGRADING.md): install a released version (FROM_REF, default v1.0.0-rc.8: its chart and an
# image built from it) with the chart's DEFAULT strategy on a fresh k3d cluster, sign in and issue tokens there
# (run.py), then upgrade to this checkout exactly as UPGRADING.md says (Recreate, with Helm 4's client-side apply for
# a release whose chart never rendered spec.strategy). Checks that old and new pods never ran at the same time, that
# the data and the tokens the old version issued survive, then rolls back as UPGRADING.md says (scale to 0, delete
# the new version's Redis sessions, helm rollback) and checks the old version is serving again.
#
# Usage (repo root): e2e/monthfold/k3d-helm-upgrade.sh
#                    SKIP_BUILD=1 ...           # use already built $IMAGE and $FROM_IMAGE
#                    KEEP=1 ...                 # leave the cluster running afterwards
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
CLUSTER=${CLUSTER:-helix-upgrade}
IMAGE=${IMAGE:-helixiam/helix-iam-server:e2e}
FROM_REF=${FROM_REF:-v1.0.0-rc.8}
FROM_IMAGE=${FROM_IMAGE:-helixiam/helix-iam-server:from-${FROM_REF//\//-}}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-Helm-Admin-Passw0rd!}
PORT=${PORT:-18090}
WORK=$(mktemp -d)
kc() { kubectl --context "k3d-$CLUSTER" -n helix "$@"; }
hl() { helm --kube-context "k3d-$CLUSTER" -n helix "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

git archive "$FROM_REF" deploy/helm/helixiam helix-iam-server | tar -x -C "$WORK"
if [ -z "${SKIP_BUILD:-}" ]; then
  docker build -q -t "$FROM_IMAGE" -f "$WORK/helix-iam-server/Dockerfile" "$WORK/helix-iam-server"
  docker build -q -t "$IMAGE" -f helix-iam-server/Dockerfile helix-iam-server
fi
k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
k3d cluster create "$CLUSTER" --no-lb --wait
k3d image import "$FROM_IMAGE" "$IMAGE" -c "$CLUSTER"
kubectl --context "k3d-$CLUSTER" create namespace helix
kc apply -f e2e/monthfold/k8s-postgres-redis.yaml
kc create secret generic helix-secrets --from-literal=db-username=helixiam --from-literal=db-password=helixiam-db-pw \
  --from-literal=db-encryption=00112233445566778899aabbccddeeff --from-literal=admin-password="$ADMIN_PASSWORD"
kc rollout status deploy/postgres --timeout=180s
kc rollout status deploy/redis --timeout=180s

PF=
trap '[ -n "$PF" ] && kill $PF 2>/dev/null; rm -rf "$WORK"; [ -n "${KEEP:-}" ] || k3d cluster delete "$CLUSTER" >/dev/null 2>&1' EXIT
forward() {
  [ -n "$PF" ] && kill "$PF" 2>/dev/null || true
  kc port-forward svc/helixiam "$PORT:8080" >/dev/null 2>&1 &
  PF=$!
  for _ in $(seq 1 30); do curl -fsS -o /dev/null "http://localhost:$PORT/actuator/health" && return 0; sleep 1; done
  fail "no answer on the port-forward"
}

# 1. The released version, default strategy (Helm 4: server-side apply).
hl install helixiam "$WORK/deploy/helm/helixiam" \
  --set image.repository="${FROM_IMAGE%:*}" --set image.tag="${FROM_IMAGE##*:}" \
  --set config.idpBaseUrl=https://idp.example.test --set config.spBaseUrl=https://console.example.test \
  --set database.host=postgres --set secrets.existingSecret=helix-secrets --set redis.host=redis \
  --set "config.allowedHosts={localhost:$PORT}"
kc rollout status deploy/helixiam --timeout=420s
[ "$(kc get deploy helixiam -o jsonpath='{.spec.strategy.type}')" = RollingUpdate ] || fail "release not on RollingUpdate"
forward
rm -rf e2e/monthfold/out
python3 e2e/monthfold/run.py --base "http://localhost:$PORT" --admin-password "$ADMIN_PASSWORD"
cp e2e/monthfold/out/tokens.json "$WORK/tokens-before.json"
echo "released version $FROM_REF: serving, tokens issued"

# 2. Upgrade as docs/UPGRADING.md says: Recreate, client-side apply (the release's chart never rendered spec.strategy).
: > "$WORK/pods.log"
( while true; do
    kc get pods -l app.kubernetes.io/name=helixiam \
      -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.spec.containers[0].image}{" "}{end}' 2>/dev/null \
      >> "$WORK/pods.log" || true
    echo >> "$WORK/pods.log"; sleep 1
  done ) &
WATCH=$!
hl upgrade helixiam deploy/helm/helixiam --reuse-values --server-side=false \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE##*:}" --set strategy.type=Recreate
kc rollout status deploy/helixiam --timeout=420s
kill $WATCH 2>/dev/null || true
[ "$(kc get deploy helixiam -o jsonpath='{.spec.strategy.type}')" = Recreate ] || fail "upgrade did not apply Recreate"
[ -z "$(kc get deploy helixiam -o jsonpath='{.spec.strategy.rollingUpdate}')" ] || fail "rollingUpdate left behind"
grep -q "$FROM_IMAGE" "$WORK/pods.log" || fail "pod watch never saw the old version"
grep -q "$IMAGE" "$WORK/pods.log" || fail "pod watch never saw the new version"
if grep "$FROM_IMAGE" "$WORK/pods.log" | grep -q "$IMAGE"; then
  fail "old and new pods ran at the same time"
fi
kc exec deploy/helixiam -- curl -fsS http://127.0.0.1:8080/actuator/health/readiness; echo
forward
curl -fsS -o /dev/null "http://localhost:$PORT/realms/monthfold/.well-known/openid-configuration" \
  || fail "the monthfold realm did not survive the upgrade"
(cd e2e/monthfold/jwxcheck && go run . "$WORK/tokens-before.json") || fail "tokens issued before the upgrade"
echo "upgraded to this checkout with Recreate: no overlap, data and earlier tokens valid"

# 2b. Later strategy changes need no client-side apply: this chart renders spec.strategy in full.
hl upgrade helixiam deploy/helm/helixiam --reuse-values --server-side=true --set strategy.type=RollingUpdate
[ "$(kc get deploy helixiam -o jsonpath='{.spec.strategy.type}')" = RollingUpdate ] || fail "back to RollingUpdate (SSA)"
hl upgrade helixiam deploy/helm/helixiam --reuse-values --server-side=true --set strategy.type=Recreate
[ "$(kc get deploy helixiam -o jsonpath='{.spec.strategy.type}')" = Recreate ] || fail "to Recreate again (SSA)"
kc rollout status deploy/helixiam --timeout=420s
echo "strategy switches both ways under server-side apply"

# 3. Rollback as docs/UPGRADING.md says: scale to 0, delete the new version's Redis sessions, helm rollback.
kc scale deploy/helixiam --replicas=0
kc wait --for=delete pod -l app.kubernetes.io/name=helixiam --timeout=180s || true
kc exec -i deploy/redis -- sh -s 'spring:session:*' < deploy/scripts/redis-delete-keys.sh
hl rollback helixiam 1
kc rollout status deploy/helixiam --timeout=420s
[ "$(kc get deploy helixiam -o jsonpath='{.spec.template.spec.containers[0].image}')" = "$FROM_IMAGE" ] \
  || fail "rollback did not restore $FROM_IMAGE"
[ "$(kc get deploy helixiam -o jsonpath='{.spec.replicas}')" -ge 1 ] || kc scale deploy/helixiam --replicas=2
kc rollout status deploy/helixiam --timeout=420s
kc exec deploy/helixiam -- curl -fsS http://127.0.0.1:8080/actuator/health/readiness; echo
forward
curl -fsS -o /dev/null "http://localhost:$PORT/realms/monthfold/.well-known/openid-configuration" \
  || fail "the rolled-back version does not serve the realm"
rm -rf e2e/monthfold/out
echo "upgrade-path gate passed: $FROM_REF -> this checkout (Recreate) -> rollback to $FROM_REF"
