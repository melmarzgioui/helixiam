// OIDC authorization_code + PKCE login for the admin console. Session-backed: the token exchange
// exists to register the sid'd OAuth2Authorization (→ Sessions screen); /admin still authorizes on
// the SESSION cookie the authorize flow establishes. Endpoints are realm-prefixed.
import { randomString, challengeFromVerifier } from "./pkce";

export const CONSOLE_CLIENT_ID = "helix-console";
const STORE_KEY = "helix.oidc";
const SCOPE = "openid profile";

interface Pending {
  verifier: string;
  state: string;
  nonce: string;
}

function redirectUri(base: string): string {
  return `${base}/console/callback`;
}

/** Build the authorize URL and persist the PKCE verifier/state/nonce for the callback. */
export async function buildAuthorizeUrl(realm: string, base: string): Promise<string> {
  const verifier = randomString(32);
  const state = randomString(16);
  const nonce = randomString(16);
  const challenge = await challengeFromVerifier(verifier);
  sessionStorage.setItem(STORE_KEY, JSON.stringify({ verifier, state, nonce } satisfies Pending));
  const q = new URLSearchParams({
    client_id: CONSOLE_CLIENT_ID,
    response_type: "code",
    redirect_uri: redirectUri(base),
    scope: SCOPE,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return `${base}/realms/${encodeURIComponent(realm)}/oauth2/authorize?${q.toString()}`;
}

/** Validate state, exchange the code for tokens, return the id_token. Clears the pending state. */
export async function exchangeCode(
  realm: string,
  params: URLSearchParams,
  redirect: string,
  storage: Storage = sessionStorage,
): Promise<{ idToken: string }> {
  const raw = storage.getItem(STORE_KEY);
  if (!raw) throw new Error("no pending OIDC login");
  const pending = JSON.parse(raw) as Pending;
  if (params.get("state") !== pending.state) throw new Error("OIDC state mismatch");
  storage.removeItem(STORE_KEY);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.get("code") ?? "",
    redirect_uri: redirect,
    client_id: CONSOLE_CLIENT_ID,
    code_verifier: pending.verifier,
  });
  const res = await fetch(`/realms/${encodeURIComponent(realm)}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    credentials: "include",
    body,
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status}`);
  const json = await res.json();
  return { idToken: json.id_token as string };
}

/** RP-initiated logout URL (end_session_endpoint), realm-prefixed, with the id_token hint. */
export function buildLogoutUrl(realm: string, idToken: string | null, base: string): string {
  const q = new URLSearchParams({ post_logout_redirect_uri: `${base}/` });
  if (idToken) q.set("id_token_hint", idToken);
  return `${base}/realms/${encodeURIComponent(realm)}/connect/logout?${q.toString()}`;
}
