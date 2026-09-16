// PKCE (RFC 7636) helpers for the console's authorization_code login. Uses the WebCrypto global
// (present in the browser and in the node/vitest test env), so no bundler or node:crypto import is
// needed. base64url everywhere — the verifier, the state/nonce, and the S256 challenge.

const toB64Url = (bytes: Uint8Array): string => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** Cryptographically-random url-safe string derived from `bytes` random bytes. */
export function randomString(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return toB64Url(buf);
}

/** base64url( SHA-256( verifier ) ) — the S256 code_challenge for `verifier`. */
export async function challengeFromVerifier(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toB64Url(new Uint8Array(digest));
}
