/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';
/*
 * Helix MCP demo — a minimal MCP-style resource server protected by Helix (OAuth 2.1 / MCP authorization).
 *
 * It demonstrates the resource-server half of MCP auth:
 *   1. Publishes RFC 9728 Protected Resource Metadata at /.well-known/oauth-protected-resource, naming
 *      Helix as its authorization server.
 *   2. Rejects an unauthenticated tool call with 401 + a RFC 9728 `WWW-Authenticate` challenge that points
 *      the client at that metadata.
 *   3. On a Bearer token: verifies the Helix-signed JWT (JWKS signature, issuer, expiry) and — crucially —
 *      that the token's `aud` is THIS server (RFC 8707 audience binding), so a token minted for another
 *      resource can't be replayed here. It also surfaces the non-human-identity (`nhi`) markers.
 *
 * Zero npm dependencies: Node's built-in `crypto` verifies RS256, PS256 and ES256 straight from a JWK.
 */
const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 9800);
const HELIX_ISSUER = process.env.HELIX_ISSUER || 'http://localhost:8083/realms/master';
const MCP_RESOURCE = process.env.MCP_RESOURCE || `http://localhost:${PORT}`;
const REQUIRED_SCOPE = process.env.MCP_REQUIRED_SCOPE || ''; // optional; empty = don't require a scope

const b64urlToJson = (s) => JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));

let jwksCache = null;
async function jwks(refresh = false) {
  if (jwksCache && !refresh) return jwksCache;
  const disc = await (await fetch(`${HELIX_ISSUER}/.well-known/openid-configuration`)).json();
  jwksCache = await (await fetch(disc.jwks_uri)).json();
  return jwksCache;
}

// The algorithms a HelixIAM realm signs with: RS256/PS256 (RSA key) or ES256 (EC P-256 key). Never 'none'/HS*.
const ALGS = {
  RS256: { hash: 'sha256' },
  PS256: { hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
  ES256: { hash: 'sha256', dsaEncoding: 'ieee-p1363' },
};

/** Verify a Helix-issued JWT: signature via JWKS (RS256/PS256/ES256, key chosen by kid), issuer, expiry, audience. */
async function verify(token) {
  const [h, p, sig] = token.split('.');
  if (!h || !p || !sig) throw new Error('malformed token');
  const header = b64urlToJson(h);
  const payload = b64urlToJson(p);
  const alg = ALGS[header.alg];
  if (!alg) throw new Error(`unsupported alg: ${header.alg}`);
  if (!header.kid) throw new Error('token has no kid');

  // A key the realm activated after we cached the JWKS: refetch once (staged keys are normally published already).
  let jwk = ((await jwks()).keys || []).find((k) => k.kid === header.kid);
  if (!jwk) jwk = ((await jwks(true)).keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('no signing key for this kid');
  if (jwk.alg && jwk.alg !== header.alg) throw new Error(`key ${header.kid} is for ${jwk.alg}, token says ${header.alg}`);
  const pub = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = crypto.verify(alg.hash, Buffer.from(`${h}.${p}`),
    { key: pub, padding: alg.padding, saltLength: alg.saltLength, dsaEncoding: alg.dsaEncoding },
    Buffer.from(sig, 'base64url'));
  if (!ok) throw new Error('bad signature');

  if (payload.iss !== HELIX_ISSUER) throw new Error(`wrong issuer: ${payload.iss}`);
  const now = Date.now() / 1000;
  if (typeof payload.exp !== 'number' || now > payload.exp) throw new Error('expired or missing exp');
  if (typeof payload.nbf === 'number' && now < payload.nbf) throw new Error('not yet valid');

  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud].filter(Boolean);
  if (!aud.includes(MCP_RESOURCE)) throw new Error(`token aud ${JSON.stringify(aud)} not bound to ${MCP_RESOURCE}`);

  if (REQUIRED_SCOPE) {
    const scopes = (payload.scope || '').split(' ');
    if (!scopes.includes(REQUIRED_SCOPE)) throw new Error(`missing scope ${REQUIRED_SCOPE}`);
  }
  return payload;
}

/** The bearer token from an Authorization header, or '' when there is none (verify() then rejects it). */
function bearerToken(header) {
  const m = /^Bearer[ ]+([A-Za-z0-9._~+/=-]+)[ ]*$/.exec(header || '');
  return m ? m[1] : '';
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body, null, 2));
}

const server = http.createServer(async (req, res) => {
  // RFC 9728 Protected Resource Metadata — how a client discovers our authorization server.
  if (req.method === 'GET' && req.url === '/.well-known/oauth-protected-resource') {
    return send(res, 200, {
      resource: MCP_RESOURCE,
      authorization_servers: [HELIX_ISSUER],
      scopes_supported: ['openid', 'mcp:tools'],
      bearer_methods_supported: ['header'],
    });
  }

  // The protected MCP endpoint (a stand-in for tools/call).
  if (req.method === 'POST' && req.url === '/mcp') {
    const metadataUrl = `${MCP_RESOURCE}/.well-known/oauth-protected-resource`;
    // Every request goes through verify(): there is no branch on the raw header that could skip it. A missing
    // or malformed header yields '' and fails verification like any other bad token.
    const token = bearerToken(req.headers.authorization);
    try {
      const claims = await verify(token);
      return send(res, 200, {
        ok: true,
        tool: 'echo',
        result: 'Hello from the Helix-protected MCP server 👋',
        caller: {
          nhi: claims.nhi === true,
          agent_id: claims.agent_id,
          agent_name: claims.agent_name,
          agent_owner: claims.agent_owner,
          subject: claims.sub,
          audience: claims.aud,
          realm_roles: claims.realm_access && claims.realm_access.roles,
          client_roles: claims.resource_access,
        },
      });
    } catch (e) {
      // MCP/RFC 9728: the challenge always tells the client where to discover how to authenticate.
      return send(res, 401, { error: 'invalid_token', error_description: String(e.message) },
        { 'WWW-Authenticate': `Bearer resource_metadata="${metadataUrl}", error="invalid_token"` });
    }
  }

  send(res, 404, { error: 'not_found' });
});

server.listen(PORT, () => {
  console.log(`[mcp-server] listening on ${MCP_RESOURCE}`);
  console.log(`[mcp-server]   authorization server: ${HELIX_ISSUER}`);
  console.log(`[mcp-server]   metadata: ${MCP_RESOURCE}/.well-known/oauth-protected-resource`);
});
