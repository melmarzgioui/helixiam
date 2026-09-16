#!/usr/bin/env bash
# Helix MCP demo — end-to-end. Provisions the demo client+agent, starts the MCP resource server,
# and runs the client through the full MCP authorization handshake against Helix.
#
# Assumes the Helix eval stack is up (publisher on :8183, postgres container helix-iam-eval-postgres-1).
set -euo pipefail
cd "$(dirname "$0")"

PG=${PG_CONTAINER:-helix-iam-eval-postgres-1}
PUB=${PUB_CONTAINER:-helix-iam-eval-authorization-server-publisher-1}
export HELIX_ISSUER=${HELIX_ISSUER:-http://localhost:8083/realms/master}
export MCP_RESOURCE=${MCP_RESOURCE:-http://localhost:9800}
export PORT=${PORT:-9800}
export CLIENT_ID=${CLIENT_ID:-mcp-agent-client}
export CLIENT_SECRET=${CLIENT_SECRET:-s3cr3t-mcp-agent-123}
export MCP_URL=${MCP_URL:-$MCP_RESOURCE/mcp}

echo "▶ Provisioning the demo client + agent in Helix (master realm)…"
docker exec -i "$PG" psql -U helix -d helix < setup.sql >/dev/null
echo "▶ Restarting the publisher so it picks up the new client…"
docker restart "$PUB" >/dev/null
for i in $(seq 1 24); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$HELIX_ISSUER/../../actuator/health/readiness" 2>/dev/null)" = "200" ] && break
  # readiness is realm-agnostic (flat /actuator path); fall back to the discovery doc as a readiness signal
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$HELIX_ISSUER/.well-known/openid-configuration" 2>/dev/null)" = "200" ] && break
  sleep 5
done

echo "▶ Starting the MCP resource server on $MCP_RESOURCE…"
node mcp-server.js &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1

echo "▶ Running the MCP client (full authorization handshake)…"
node mcp-client.js

echo "▶ Negative test — a token bound to a different resource must be rejected (RFC 8707)…"
node test-aud-binding.js
