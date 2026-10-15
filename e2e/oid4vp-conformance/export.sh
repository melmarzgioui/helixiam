#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Exports every plan of a run from the suite (its JSON export), strips secrets (driver/redact.mjs: private JWK members,
# PEM private keys, response codes; screenshots become JPEG files), gzips the logs and copies them, with the driver's
# per-module results, to docs/compliance/oid4vp-conformance/<date>/. Usage: export.sh <run label> <date>
# The suite's .sig signature files are dropped: they no longer verify once the logs are redacted.
set -euo pipefail
. "$(dirname "$0")/env.sh"
RUN=$1; DATE=$2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DST=$ROOT/docs/compliance/oid4vp-conformance/$DATE
X=$OIDF_WORK/export/$RUN; rm -rf "$X"; mkdir -p "$X/json"
PIN=$(openssl x509 -in "$OIDF_WORK/pki/suite-nginx.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
for f in "$OIDF_WORK/runs/$RUN"/*-results.json; do
  label=$(jq -r .label "$f"); id=$(jq -r .planId "$f")
  # -k only skips the CA check of the suite's self-signed certificate; the key itself is pinned
  curl -fsS -k --pinnedpubkey "sha256//$PIN" -o "$X/json/$label.zip" "https://localhost:$OIDF_SUITE_PORT/api/plan/export/$id"
done
rm -rf "$X/redacted"; node "$(dirname "$0")/driver/redact.mjs" "$X" "$X/redacted"
find "$X/redacted" -name '*.json' -exec gzip -9n {} \;
mkdir -p "$DST"
cp -R "$X/redacted/." "$DST/"
jq -s '[.[] | {label, planName, planId, variant, alias, flow, modules: [.modules[] | {module, testId, alias, status, result,
  helixFinalUrl, findings: [.findings[] | select(.result != "REVIEW")]}]}]' "$OIDF_WORK/runs/$RUN"/*-results.json > "$DST/results.json"
echo "exported to $DST"
