// Pure helpers for inspecting tokens in the sandbox UI.
// No verification here — the RP library already validated signatures during the
// code exchange. These functions exist only to *display* what the tokens carry.

/** The registered OIDC standard claims (id_token + access_token + userinfo). */
const STANDARD_CLAIMS = new Set([
  // id_token core
  'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp',
  'sid', 'at_hash', 'c_hash', 'nbf', 'jti', 'typ', 'scope', 'client_id',
  // profile scope
  'name', 'family_name', 'given_name', 'middle_name', 'nickname',
  'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate',
  'zoneinfo', 'locale', 'updated_at',
  // email / phone / address scopes
  'email', 'email_verified', 'phone_number', 'phone_number_verified', 'address',
]);

/** Unix-epoch (seconds) claims worth rendering as a human-readable timestamp. */
const TIME_CLAIMS = new Set(['exp', 'iat', 'auth_time', 'nbf', 'updated_at']);

/**
 * Decode a JWT's payload segment without verifying it.
 * @returns the claims object, or null if the input isn't a well-formed JWT.
 */
export function decodeJwt(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function renderValue(key, value) {
  if (TIME_CLAIMS.has(key) && typeof value === 'number') {
    return `${value} (${new Date(value * 1000).toISOString()})`;
  }
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

/**
 * Split a claims object into recognised OIDC standard claims and everything
 * else (realm/client roles, custom mappers …), each as {key, value, display}.
 */
export function groupClaims(claims) {
  const standard = [];
  const custom = [];
  for (const [key, value] of Object.entries(claims || {})) {
    const entry = { key, value, display: renderValue(key, value) };
    (STANDARD_CLAIMS.has(key) ? standard : custom).push(entry);
  }
  const byKey = (a, b) => a.key.localeCompare(b.key);
  return { standard: standard.sort(byKey), custom: custom.sort(byKey) };
}
