#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Seeds realm $OIDF_REALM for a conformance run: the verifier access key (leaf + intermediate, never the root), a test
# user, and one wallet identity provider per (credential format, client_id prefix[, request_uri_method]):
#   w-<sdjwt|mdoc>-<hash|san>[-post]   responseMode direct_post.jwt   (seed.sh)
#   w-<sdjwt|mdoc>-<hash|san>-plain    responseMode direct_post       (seed.sh direct_post; dev profile only)
# Trust anchors: the run's SD-JWT issuer root and the suite's mdoc IACA root. revocationChecking=OFF because neither
# test issuer publishes a reachable CRL/OCSP endpoint (the suite's IACA names http://example.com/myca.crl).
# subject.acknowledgeWeakSubject=true: the suite's PIDs carry no personal_administrative_number, so a sign-in needs a
# wallet linked to an account first (driver spec "linkUser"); the attribute-tuple subject is what makes that link.
set -euo pipefail
. "$(dirname "$0")/env.sh"
P=$OIDF_WORK/pki; B=http://localhost:$OIDF_HELIX_PORT; REALM=$OIDF_REALM; MODE=${1:-direct_post.jwt}
curl -fsS -X PUT "$B/admin/realms/$REALM/settings" -H 'Content-Type: application/json' \
  -d '{"displayName":"OIDF conformance","enabled":true,"accessTokenTtlSeconds":300,"refreshTokenTtlSeconds":86400,"passwordMinLength":8,"registrationEnabled":false}' >/dev/null
KEY_REF=$(curl -fsS "$B/admin/realms/$REALM/verifier-keys" | jq -r '.[] | select(.name=="oidf-access") | .keyRef' | head -n1)
if [ -z "$KEY_REF" ]; then
  KEY_REF=$(jq -n --rawfile k "$P/vleaf.key" --rawfile c "$P/vchain.pem" '{name:"oidf-access",privateKeyPem:$k,certificateChainPem:$c}' \
    | curl -fsS -X POST "$B/admin/realms/$REALM/verifier-keys" -H 'Content-Type: application/json' -d @- | jq -r .keyRef)
fi
echo "verifier key: $KEY_REF"
jq -n --rawfile p "$P/userpw" '{username:"jean.dupont", email:"jean.dupont@oidf.example", password:($p|rtrimstr("\n")), enabled:true}' \
  | curl -sS -o /dev/null -X POST "$B/admin/realms/$REALM/users" -H 'Content-Type: application/json' -d @- || true
ANCHORS=$(cat "$P/iroot.pem" "$P/iaca-root.pem")
put() { # alias body
  if [ "$(curl -sS -o /dev/null -w '%{http_code}' "$B/admin/realms/$REALM/identity-providers/$1")" = 200 ]; then
    curl -fsS -o /dev/null -X PUT "$B/admin/realms/$REALM/identity-providers/$1" -H 'Content-Type: application/json' -d "$2"
  else
    curl -fsS -o /dev/null -X POST "$B/admin/realms/$REALM/identity-providers" -H 'Content-Type: application/json' -d "$2"
  fi
  echo "provider: $1"
}
for fmt in sdjwt mdoc; do for cid in hash san; do for method in get post; do
  [ "$MODE" = direct_post ] && [ "$method" = post ] && continue
  alias="w-$fmt-$cid"
  if [ "$MODE" = direct_post ]; then alias="$alias-plain"; fi
  if [ "$method" = post ]; then alias="$alias-post"; fi
  body=$(jq -n --arg a "$alias" --arg k "$KEY_REF" --arg t "$ANCHORS" --arg m "$MODE" --arg h "$OIDF_HOST" --arg rm "$method" \
    --arg f "$([ $fmt = sdjwt ] && echo '["dc+sd-jwt"]' || echo '["mso_mdoc"]')" \
    --arg s "$([ $cid = hash ] && echo x509_hash || echo x509_san_dns)" \
    '{alias:$a, protocol:"eudi-wallet", displayName:("OIDF " + $a), enabled:true,
      config:({accessKeyRef:$k, trustAnchors:$t, credentialFormats:$f, clientIdScheme:$s, responseMode:$m,
               requestUriMethod:$rm, revocationChecking:"OFF", "subject.acknowledgeWeakSubject":"true"}
              + (if $s == "x509_san_dns" then {clientIdHost:$h} else {} end))}')
  put "$alias" "$body"
done; done; done
