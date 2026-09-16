/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';
/*
 * Negative test — proves the MCP server enforces RFC 8707 audience binding.
 *
 * It mints TWO real Helix tokens for the same agent client:
 *   A. resource = this MCP server        → the server MUST accept it (200)
 *   B. resource = a DIFFERENT server     → the server MUST reject it (401), because the token's `aud`
 *      is bound to the other resource and cannot be replayed here.
 *
 * Assumes the MCP server (mcp-server.js) is already running and Helix is reachable. Zero dependencies.
 * Exits 0 only if BOTH expectations hold.
 */
const HELIX_ISSUER = process.env.HELIX_ISSUER || 'http://localhost:8083/realms/master';
const MCP_URL = process.env.MCP_URL || 'http://localhost:9800/mcp';
const MCP_RESOURCE = process.env.MCP_RESOURCE || 'http://localhost:9800';
const OTHER_RESOURCE = process.env.OTHER_RESOURCE || 'http://localhost:9999';
const CLIENT_ID = process.env.CLIENT_ID || 'mcp-agent-client';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 's3cr3t-mcp-agent-123';

async function tokenFor(resource) {
  const disc = await (await fetch(`${HELIX_ISSUER}/.well-known/openid-configuration`)).json();
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const res = await fetch(disc.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
    body: new URLSearchParams({ grant_type: 'client_credentials', resource, scope: 'openid' }),
  });
  const tok = await res.json();
  if (!tok.access_token) throw new Error(`token request failed: ${JSON.stringify(tok)}`);
  return tok.access_token;
}

async function callMcp(token) {
  const res = await fetch(MCP_URL, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: '{}' });
  return res.status;
}

async function main() {
  let failures = 0;

  const good = await tokenFor(MCP_RESOURCE);
  const goodStatus = await callMcp(good);
  if (goodStatus === 200) console.log(`✓ token bound to ${MCP_RESOURCE} accepted (200)`);
  else { console.error(`✗ expected 200 for correctly-bound token, got ${goodStatus}`); failures++; }

  const wrong = await tokenFor(OTHER_RESOURCE);
  const wrongStatus = await callMcp(wrong);
  if (wrongStatus === 401) console.log(`✓ token bound to ${OTHER_RESOURCE} REJECTED (401) — aud binding enforced`);
  else { console.error(`✗ expected 401 for wrong-audience token, got ${wrongStatus}`); failures++; }

  console.log(failures === 0
    ? '\n\x1b[32m✓ aud-binding enforced: a token for another resource cannot be replayed here.\x1b[0m'
    : `\n\x1b[31m✗ ${failures} assertion(s) failed.\x1b[0m`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('\n\x1b[31mTest failed:\x1b[0m', e.message); process.exit(1); });
