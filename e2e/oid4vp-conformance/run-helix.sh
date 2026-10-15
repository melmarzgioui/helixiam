#!/usr/bin/env bash
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Runs the built HelixIAM jar on the host for a conformance run. Usage: run-helix.sh prod|dev
#   prod  the default (non-dev) profile: direct_post.jwt only, allowed-hosts enforced, cookies Secure
#   dev   the dev profile, the only one where a provider may use the unencrypted direct_post response mode
# Both run behind the TLS proxy (stack.sh proxy): IDP_BASE_URL is https://$OIDF_HOST:$OIDF_TLS_PORT, the proxy's
# forwarded headers are trusted from the loopback peer Docker Desktop connects from, and the admin API is opened with
# helix.admin.dev-open so the harness can seed it from the host. That last setting is a TEST-HARNESS-ONLY convenience.
set -euo pipefail
. "$(dirname "$0")/env.sh"
P=$OIDF_WORK/pki
export SERVER_PORT=$OIDF_HELIX_PORT DB_HOST=localhost DB_RO_HOST=localhost DB_PORT=$OIDF_PG_PORT DB_NAME=helixiam \
  DB_USERNAME=helix DB_PASSWORD=helix
DB_ENCRYPTION=$(cat "$P/dbenc"); export DB_ENCRYPTION
export IDP_BASE_URL="https://$OIDF_HOST:$OIDF_TLS_PORT" SP_BASE_URL="https://$OIDF_HOST:$OIDF_TLS_PORT"
export HELIX_CONSOLE_BASE_URL=$IDP_BASE_URL HELIX_SAML_IDP_ENTITY_ID="$IDP_BASE_URL/realms/master"
export HELIX_SESSION_STORE=queue HELIX_TOKEN_STORE=queue MFA_ENABLED=false
export HELIX_TRUSTED_PROXIES=127.0.0.1/32,::1/128
export HELIX_ALLOWED_HOSTS="$OIDF_HOST:$OIDF_TLS_PORT"
HELIX_ADMIN_PASSWORD=$(cat "$P/adminpw"); export HELIX_ADMIN_USERNAME=admin HELIX_ADMIN_PASSWORD
export HELIX_ADMIN_DEV_OPEN=true
if [ "${1:-prod}" = dev ]; then export SPRING_PROFILES_ACTIVE=dev; fi
exec java -jar "$OIDF_HELIX_JAR" --idp.base.url="$IDP_BASE_URL" --sp.base.url="$SP_BASE_URL" \
  > "$OIDF_WORK/helix-${1:-prod}.log" 2>&1
