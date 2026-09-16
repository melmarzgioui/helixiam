/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';
/*
 * Helix MCP demo — the client half. Runs the full MCP authorization handshake against a Helix-protected
 * MCP server, printing every step:
 *
 *   1. Call the MCP server with no token          → 401 + WWW-Authenticate: resource_metadata="…"
 *   2. Fetch the RFC 9728 Protected Resource Metadata → discover the authorization server + resource id
 *   3. Fetch the AS's OIDC discovery              → find the token endpoint
 *   4. Get a client_credentials token from Helix, passing resource=<mcp resource> (RFC 8707)
 *      → the token's `aud` binds to this one MCP server
 *   5. Retry the MCP call with the bearer token   → 200
 *
 * The client authenticates as an AGENT's bound OAuth client; the token it gets carries the agent's `nhi.*`
 * identity, which the MCP server surfaces. Zero npm dependencies.
 */
const CLIENT_ID = process.env.CLIENT_ID || 'mcp-agent-client';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 's3cr3t-mcp-agent-123';
const MCP_URL = process.env.MCP_URL || 'http://localhost:9800/mcp';

const b64urlToJson = (s) => JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
const step = (n, msg) => console.log(`\n\x1b[1m[${n}]\x1b[0m ${msg}`);

async function main() {
  // 1. Unauthenticated call → discover the challenge.
  step(1, `Calling the MCP server unauthenticated: POST ${MCP_URL}`);
  let res = await fetch(MCP_URL, { method: 'POST', body: '{}' });
  console.log(`    → ${res.status} ${res.statusText}`);
  const challenge = res.headers.get('www-authenticate') || '';
  console.log(`    WWW-Authenticate: ${challenge}`);
  const metaUrl = (challenge.match(/resource_metadata="([^"]+)"/) || [])[1];
  if (!metaUrl) throw new Error('no resource_metadata in the WWW-Authenticate challenge');

  // 2. Fetch RFC 9728 Protected Resource Metadata.
  step(2, `Fetching Protected Resource Metadata (RFC 9728): ${metaUrl}`);
  const meta = await (await fetch(metaUrl)).json();
  console.log(`    resource=${meta.resource}`);
  console.log(`    authorization_servers=${JSON.stringify(meta.authorization_servers)}`);
  const as = meta.authorization_servers[0];
  const resource = meta.resource;

  // 3. Fetch the authorization server's OIDC discovery.
  step(3, `Fetching authorization-server metadata: ${as}/.well-known/openid-configuration`);
  const disc = await (await fetch(`${as}/.well-known/openid-configuration`)).json();
  console.log(`    token_endpoint=${disc.token_endpoint}`);

  // 4. Get an audience-bound token (client_credentials as the agent's client, resource=<mcp>).
  step(4, `Requesting a token bound to the MCP server (resource=${resource})`);
  const form = new URLSearchParams({ grant_type: 'client_credentials', resource, scope: 'openid' });
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const tokRes = await fetch(disc.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
    body: form,
  });
  const tok = await tokRes.json();
  if (!tok.access_token) throw new Error(`token request failed: ${JSON.stringify(tok)}`);
  const claims = b64urlToJson(tok.access_token.split('.')[1]);
  console.log(`    → token issued. aud=${JSON.stringify(claims.aud)}  nhi=${claims.nhi}  agent=${claims.agent_name || claims.agent_id}`);

  // 5. Retry the MCP call with the bearer token.
  step(5, `Retrying the MCP call WITH the bearer token`);
  res = await fetch(MCP_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tok.access_token}` },
    body: '{}',
  });
  const out = await res.json();
  console.log(`    → ${res.status} ${res.statusText}`);
  console.log(JSON.stringify(out, null, 2));

  console.log(res.status === 200 && out.ok
    ? '\n\x1b[32m✓ MCP authorization succeeded: agent authorized against a Helix-protected MCP server.\x1b[0m'
    : '\n\x1b[31m✗ MCP call did not succeed.\x1b[0m');
  process.exit(res.status === 200 && out.ok ? 0 : 1);
}

main().catch((e) => { console.error('\n\x1b[31mDemo failed:\x1b[0m', e.message); process.exit(1); });
