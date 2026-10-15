#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Creates the throwaway PKI of a conformance run in $OIDF_WORK/pki (never in the repository):
#   - tls-*      a local CA and the TLS certificate of the proxy in front of HelixIAM ($OIDF_HOST)
#   - v*         the verifier access certificate: root -> intermediate -> leaf with SAN DNS:$OIDF_HOST (x509_san_dns),
#                imported into HelixIAM as leaf + intermediate; the root is the suite's request-object trust anchor
#   - i*         the SD-JWT VC issuer the suite signs PIDs with: root -> document signer (x5c = [leaf])
#   - iaca-root  the suite's own mdoc IACA root (published by the suite), a HelixIAM trust anchor for mso_mdoc
#   - config-*.json the suite test configurations (they carry the issuer's private JWK: keep them local)
# Idempotent: existing material is reused. Needs openssl, curl, node; the suite must be up (stack.sh up) for the IACA.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/env.sh"
P=$OIDF_WORK/pki; cd "$P"
H=$OIDF_HOST
ec() { [ -f "$1" ] || openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$1"; }

if [ ! -f tls.pem ]; then
  ec tls-ca.key
  openssl req -x509 -new -key tls-ca.key -sha256 -days 30 -subj "/CN=OIDF local TLS CA" \
    -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" -out tls-ca.pem
  ec tls.key; openssl req -new -key tls.key -subj "/CN=$H" -out tls.csr
  printf "subjectAltName=DNS:$H\nbasicConstraints=CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" > tls.ext
  openssl x509 -req -in tls.csr -CA tls-ca.pem -CAkey tls-ca.key -CAcreateserial -days 30 -sha256 -extfile tls.ext -out tls.pem
  cat tls.pem tls-ca.pem > tls-fullchain.pem
fi
if [ ! -f vchain.pem ]; then
  ec vroot.key
  openssl req -x509 -new -key vroot.key -sha256 -days 365 -subj "/C=NL/O=HelixIAM conformance/CN=OIDF test verifier root" \
    -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out vroot.pem
  ec vint.key; openssl req -new -key vint.key -subj "/C=NL/O=HelixIAM conformance/CN=OIDF test verifier intermediate" -out vint.csr
  printf "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > vint.ext
  openssl x509 -req -in vint.csr -CA vroot.pem -CAkey vroot.key -CAcreateserial -days 365 -sha256 -extfile vint.ext -out vint.pem
  ec vleaf.key; openssl req -new -key vleaf.key -subj "/C=NL/O=HelixIAM conformance/CN=$H" -out vleaf.csr
  printf "subjectAltName=DNS:$H\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > vleaf.ext
  openssl x509 -req -in vleaf.csr -CA vint.pem -CAkey vint.key -CAcreateserial -days 180 -sha256 -extfile vleaf.ext -out vleaf.pem
  cat vleaf.pem vint.pem > vchain.pem
fi
if [ ! -f ids.pem ]; then
  ec iroot.key
  openssl req -x509 -new -key iroot.key -sha256 -days 365 -subj "/C=FR/O=OIDF suite test issuer/CN=OIDF test PID issuer root" \
    -addext "basicConstraints=critical,CA:true,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out iroot.pem
  ec ids.key; openssl req -new -key ids.key -subj "/C=FR/O=OIDF suite test issuer/CN=OIDF test PID document signer" -out ids.csr
  printf "basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > ids.ext
  openssl x509 -req -in ids.csr -CA iroot.pem -CAkey iroot.key -CAcreateserial -days 180 -sha256 -extfile ids.ext -out ids.pem
fi
# the suite's IACA root (its mdocs' x5chain carries only a DS certificate minted under it) and its nginx certificate
curl -fsSk "https://localhost:$OIDF_SUITE_PORT/mdoc-iaca-root.pem" -o iaca-root.pem
echo | openssl s_client -connect "localhost:$OIDF_SUITE_PORT" -servername localhost 2>/dev/null | openssl x509 > suite-nginx.pem
# Chromium accepts exactly the proxy's key (SPKI pin) instead of ignoring every certificate error
openssl x509 -in tls.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 > tls-spki.txt
[ -f dbenc ] || openssl rand -hex 16 > dbenc
[ -f adminpw ] || openssl rand -hex 12 > adminpw
[ -f userpw ] || echo "Oidf-$(openssl rand -hex 8)!" > userpw
node "$HERE/driver/mkconfig.mjs" "$P"
openssl verify -CAfile vroot.pem -untrusted vint.pem vleaf.pem >/dev/null
openssl verify -CAfile iroot.pem ids.pem >/dev/null
echo "PKI ready in $P"
