import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeJwt, groupClaims } from '../lib/jwt.js';

// A JWT is header.payload.signature with base64url-encoded JSON segments.
// Build one by hand so the test owns the expected payload exactly.
function makeJwt(payload) {
  const b64url = (obj) =>
    Buffer.from(JSON.stringify(obj)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url(payload)}.c2ln`;
}

test('decodeJwt returns the decoded payload claims', () => {
  const token = makeJwt({ sub: 'abc', name: 'Sandbox User', iat: 1700000000 });
  const claims = decodeJwt(token);
  assert.equal(claims.sub, 'abc');
  assert.equal(claims.name, 'Sandbox User');
  assert.equal(claims.iat, 1700000000);
});

test('decodeJwt handles base64url payloads needing padding', () => {
  // payload length chosen so base64 needs '=' padding once stripped
  const token = makeJwt({ a: 'b' });
  assert.deepEqual(decodeJwt(token), { a: 'b' });
});

test('decodeJwt returns null for a non-JWT string', () => {
  assert.equal(decodeJwt('not-a-jwt'), null);
  assert.equal(decodeJwt(''), null);
  assert.equal(decodeJwt(undefined), null);
});

test('groupClaims splits standard vs custom and converts epoch times', () => {
  const grouped = groupClaims({
    sub: 'u1',
    iss: 'http://idp/realms/master',
    auth_time: 1700000000,
    exp: 1700000300,
    realm_roles: ['admin'],
    custom_thing: 'x',
  });
  // standard OIDC claims recognised
  assert.ok(grouped.standard.some((c) => c.key === 'sub'));
  assert.ok(grouped.standard.some((c) => c.key === 'iss'));
  // unknown claims land in custom
  assert.ok(grouped.custom.some((c) => c.key === 'custom_thing'));
  assert.ok(grouped.custom.some((c) => c.key === 'realm_roles'));
  // time claims get a human-readable rendering alongside the raw epoch
  const authTime = [...grouped.standard, ...grouped.custom].find((c) => c.key === 'auth_time');
  assert.match(authTime.display, /\d{4}-\d{2}-\d{2}/);
});
