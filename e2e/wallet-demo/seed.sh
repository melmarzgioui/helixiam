#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Task 25: seeds a demo realm for "Sign in with EUDI Wallet" against a running helix-iam-server (dev profile) and
# the helix-sandbox-rp relying party — so the whole OpenID4VP verifier flow can be tried by hand with the test
# wallet CLI (io.helixiam.testwallet.TestWalletCli), with no phone required. See helix-sandbox-rp/README.md for the
# walkthrough this feeds.
#
# Lives under e2e/ (not helix-sandbox-rp/) to match the house style of the other seed scripts here
# (e2e/monthfold/run.py): sandbox-rp stays a plain relying-party app with no server-provisioning concerns of its
# own, and every "seed a realm against a running server" script lives in one place.
#
# Response mode: this seeds responseMode=direct_post.jwt (encrypted), the WalletProviderConfig default, with
# DB_ENCRYPTION set — the dev profile (application-dev.properties) already sets a default DB_ENCRYPTION, so no
# extra env is required to get the encrypted, e2e-base-like path. Plaintext direct_post is a dev-only allowance;
# this script does not use it.
#
# Idempotent: re-running reuses the CA material already written to --ca-dir, reuses an already-imported verifier
# key (by name), PUTs (never duplicates) the identity-provider connection, and reveals (never rotates) an
# already-created sandbox client's secret.
#
# Usage (repo root): e2e/wallet-demo/seed.sh
#   HELIX_BASE=http://localhost:8080        the running dev server (must have HELIX_ADMIN_DEV_OPEN=true — see
#                                           helix-sandbox-rp/README.md's "Sign in with EUDI Wallet" section)
#   WALLET_DEMO_REALM=wallet-demo            realm to create/update
#   WALLET_DEMO_ALIAS=eudi-wallet            identity-provider alias
#   WALLET_DEMO_CLIENT_ID=helix-sandbox      the sandbox RP's OIDC client in this realm
#   WALLET_DEMO_REDIRECT=http://localhost:9090/callback
#
# Needs: curl, jq, and (for a first run) a JDK + Maven able to run `mvn exec:java` against helix-iam-server's test
# classpath (same requirement as the rest of this repo's test suite).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="$ROOT/e2e/wallet-demo/out"
mkdir -p "$OUT_DIR"

BASE=${HELIX_BASE:-http://localhost:8080}
REALM=${WALLET_DEMO_REALM:-wallet-demo}
ALIAS=${WALLET_DEMO_ALIAS:-eudi-wallet}
CLIENT_ID=${WALLET_DEMO_CLIENT_ID:-helix-sandbox}
REDIRECT_URI=${WALLET_DEMO_REDIRECT:-http://localhost:9090/callback}
CA_DIR=${WALLET_DEMO_CA_DIR:-"$OUT_DIR/wallet-demo-ca"}
ENV_FILE="$OUT_DIR/sandbox.env"

for tool in curl jq mvn; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

echo "== checking $BASE is up =="
if ! curl -fsS "$BASE/actuator/health/readiness" >/dev/null; then
  cat >&2 <<EOF
$BASE is not answering /actuator/health/readiness.
Start the server first (dev profile, admin API open for this demo), e.g.:

  cd helix-iam-server
  mvn -q clean package -DskipTests
  SPRING_PROFILES_ACTIVE=dev HELIX_ADMIN_DEV_OPEN=true \\
    java -jar target/helix-iam-server-*.jar

See helix-sandbox-rp/README.md for the full walkthrough.
EOF
  exit 1
fi

echo "== test PID-issuer CA + verifier access key =="
if [ -f "$CA_DIR/pid-issuer-ca.pem" ] && [ -f "$CA_DIR/verifier-key.pem" ] && [ -f "$CA_DIR/verifier-chain.pem" ]; then
  echo "reusing existing CA material at $CA_DIR"
else
  ( cd "$ROOT/helix-iam-server" && mvn -q exec:java -Dexec.classpathScope=test \
      -Dexec.mainClass=io.helixiam.testwallet.TestWalletCli -Dexec.args="ca --out $CA_DIR" )
fi
PID_CA_PEM=$(cat "$CA_DIR/pid-issuer-ca.pem")
VERIFIER_KEY_PEM=$(cat "$CA_DIR/verifier-key.pem")
VERIFIER_CHAIN_PEM=$(cat "$CA_DIR/verifier-chain.pem")

echo "== realm $REALM (create or update) =="
curl -fsS -X PUT "$BASE/admin/realms/$REALM/settings" -H 'Content-Type: application/json' \
  -d '{"displayName":"EUDI Wallet Demo","enabled":true,"accessTokenTtlSeconds":300,"refreshTokenTtlSeconds":86400,"passwordMinLength":8,"registrationEnabled":true}' \
  >/dev/null

echo "== verifier access key =="
KEY_NAME="wallet-demo-access"
EXISTING_KEY_REF=$(curl -fsS "$BASE/admin/realms/$REALM/verifier-keys" | jq -r --arg n "$KEY_NAME" '.[] | select(.name == $n) | .keyRef' | head -n1)
if [ -n "$EXISTING_KEY_REF" ]; then
  KEY_REF="$EXISTING_KEY_REF"
  echo "reusing existing verifier key $KEY_REF"
else
  KEY_REF=$(jq -n --arg name "$KEY_NAME" --arg key "$VERIFIER_KEY_PEM" --arg chain "$VERIFIER_CHAIN_PEM" \
      '{name: $name, privateKeyPem: $key, certificateChainPem: $chain}' \
    | curl -fsS -X POST "$BASE/admin/realms/$REALM/verifier-keys" -H 'Content-Type: application/json' -d @- \
    | jq -r '.keyRef')
  echo "imported verifier key $KEY_REF"
fi

echo "== identity provider $ALIAS (eudi-wallet) =="
IDP_BODY=$(jq -n --arg alias "$ALIAS" --arg displayName "EU Digital Identity Wallet" \
    --arg keyRef "$KEY_REF" --arg trustAnchors "$PID_CA_PEM" \
    '{alias: $alias, protocol: "eudi-wallet", displayName: $displayName, enabled: true,
      config: {accessKeyRef: $keyRef, trustAnchors: $trustAnchors, revocationChecking: "OFF"}}')
IDP_STATUS=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/admin/realms/$REALM/identity-providers/$ALIAS")
if [ "$IDP_STATUS" = "200" ]; then
  curl -fsS -X PUT "$BASE/admin/realms/$REALM/identity-providers/$ALIAS" -H 'Content-Type: application/json' \
    -d "$IDP_BODY" >/dev/null
  echo "updated identity provider $ALIAS"
else
  curl -fsS -X POST "$BASE/admin/realms/$REALM/identity-providers" -H 'Content-Type: application/json' \
    -d "$IDP_BODY" >/dev/null
  echo "created identity provider $ALIAS"
fi

echo "== sandbox RP client $CLIENT_ID =="
EXISTING_CLIENT_ID=$(curl -fsS "$BASE/admin/realms/$REALM/clients" | jq -r --arg c "$CLIENT_ID" '.[] | select(.clientId == $c) | .id' | head -n1)
if [ -n "$EXISTING_CLIENT_ID" ]; then
  CLIENT_SECRET=$(curl -fsS "$BASE/admin/realms/$REALM/clients/$EXISTING_CLIENT_ID/secret" | jq -r '.secret')
  echo "reusing existing client $CLIENT_ID"
else
  CLIENT_BODY=$(jq -n --arg clientId "$CLIENT_ID" --arg redirect "$REDIRECT_URI" \
      '{clientId: $clientId, grantTypes: ["authorization_code", "refresh_token"], redirectUris: [$redirect],
        scopes: ["openid", "profile", "email"]}')
  CLIENT_SECRET=$(curl -fsS -X POST "$BASE/admin/realms/$REALM/clients" -H 'Content-Type: application/json' \
    -d "$CLIENT_BODY" | jq -r '.secret')
  echo "created client $CLIENT_ID"
fi

cat > "$ENV_FILE" <<EOF
# Generated by e2e/wallet-demo/seed.sh — source this before starting helix-sandbox-rp.
export HELIX_ISSUER=$BASE/realms/$REALM
export HELIX_CLIENT_ID=$CLIENT_ID
export HELIX_CLIENT_SECRET=$CLIENT_SECRET
export HELIX_REDIRECT_URI=$REDIRECT_URI
export HELIX_SCOPE="openid profile email"
export COOKIE_SECURE=false
EOF

echo
echo "Seed complete."
echo "  Realm:            $REALM"
echo "  Wallet IdP alias:  $ALIAS"
echo "  Sandbox client:    $CLIENT_ID"
echo "  Sandbox RP env:    $ENV_FILE"
echo
echo "Next: source $ENV_FILE, start helix-sandbox-rp, and open http://localhost:9090/login"
echo "      — see helix-sandbox-rp/README.md, 'Sign in with EUDI Wallet'."
