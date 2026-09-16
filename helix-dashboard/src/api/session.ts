/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Helix admin console — session auth wiring for the browser. The console is a session-cookie app: the
// admin logs in at the auth server's login page, and every /admin call rides that session. Two concerns:
//   1. mutating requests must echo the JS-readable XSRF-TOKEN cookie in the X-XSRF-TOKEN header, and
//      requests must send the session cookie (credentials: "include");
//   2. when the session is missing/expired, the app must send the browser to the login page.
// We install these globally by wrapping window.fetch so every existing api client (all plain fetch())
// gets them without change. Pure CSRF logic lives in ./csrf and is unit-tested.

import { csrfHeaders, needsCsrf } from "./csrf";
import { buildAuthorizeUrl, buildLogoutUrl, exchangeCode } from "./oidc";

/** Realm the admin authenticates against (where the admin user lives). */
const ADMIN_REALM = "master";
const LOGIN_URL = `/realms/${ADMIN_REALM}/login`;
const LOGOUT_URL = `/realms/${ADMIN_REALM}/logout`;
/** Where the console lands after /oauth2/authorize (must match the seeded helix-console redirect URI). */
const CALLBACK_PATH = "/console/callback";
/** The id_token from the OIDC login, kept for the RP-logout id_token_hint. */
export const ID_TOKEN_KEY = "helix.idtoken";

let redirecting = false;

/** The console's own origin — the base for OIDC redirect/logout URLs. */
export function consoleBaseUrl(): string {
  return window.location.origin;
}

/** Start the OIDC authorization_code + PKCE login (registers the SSO session). Idempotent within a tick. */
export async function startLogin(realm: string = ADMIN_REALM): Promise<void> {
  if (redirecting) return;
  redirecting = true;
  const url = await buildAuthorizeUrl(realm, consoleBaseUrl());
  window.location.assign(url);
}

/** Break-glass: go straight to the IdP form-login (no OIDC), for recovery if the console client breaks. */
export function goToLoginDirect(): void {
  if (redirecting) return;
  redirecting = true;
  window.location.assign(LOGIN_URL);
}

/** Send the browser to (re)login. Restarts the OIDC flow so the new session is SSO-registered. */
export function goToLogin(): void {
  void startLogin();
}

/** If we're on the OIDC callback, exchange the code (creates the sid'd authorization), store the id_token,
 *  and rewrite the URL to the app home. Returns true when a callback was handled. Throws on failure. */
export async function handleCallback(): Promise<boolean> {
  if (window.location.pathname !== CALLBACK_PATH) return false;
  const params = new URLSearchParams(window.location.search);
  const { idToken } = await exchangeCode(ADMIN_REALM, params, `${consoleBaseUrl()}${CALLBACK_PATH}`);
  if (idToken) sessionStorage.setItem(ID_TOKEN_KEY, idToken);
  window.history.replaceState({}, "", `/realms/${ADMIN_REALM}/providers`);
  return true;
}

/** The signed-in admin, as shown in the console header. */
export interface AdminIdentity {
  name: string;
  email?: string;
}

/** Fetch the current admin's identity from the session-gated account profile. Null if not resolvable. */
export async function fetchProfile(): Promise<AdminIdentity | null> {
  try {
    const res = await window.fetch(SESSION_PROBE, { redirect: "manual" });
    if (!res.ok) return null;
    const p = await res.json();
    const name = p.username || p.email || "Admin";
    return { name, email: p.email || undefined };
  } catch {
    return null;
  }
}

/** End the admin session: CSRF-protected POST /logout kills the cookie session, then RP-logout
 *  (/connect/logout with id_token_hint) clears the OIDC/SSO session and lands back on the console. */
export async function logout(): Promise<void> {
  try {
    // The wrapped fetch adds credentials + the X-XSRF-TOKEN header that /logout requires.
    await window.fetch(LOGOUT_URL, { method: "POST" });
  } catch {
    /* fall through — navigate to RP-logout regardless */
  }
  const idToken = sessionStorage.getItem(ID_TOKEN_KEY);
  sessionStorage.removeItem(ID_TOKEN_KEY);
  window.location.assign(buildLogoutUrl(ADMIN_REALM, idToken, consoleBaseUrl()));
}

/** True when a response means "no valid session" for a same-origin API call. */
function isUnauthenticated(res: Response, method: string): boolean {
  if (res.status === 401) return true;
  // A mutating call rejected for a missing/expired session or CSRF token surfaces as 403/405 here; a
  // redirect to the login page (opaqueredirect / a Location to /login) means the session lapsed.
  if (res.type === "opaqueredirect") return true;
  if (needsCsrf(method) && (res.status === 403 || res.status === 405)) return true;
  return false;
}

/** Install the global fetch wrapper. Call once, before the app renders. */
export function installSessionFetch(): void {
  const original = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const method = (init.method ?? (typeof input !== "string" && "method" in (input as Request) ? (input as Request).method : "GET")) || "GET";
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const sameOrigin = url.startsWith("/") || url.startsWith(window.location.origin);
    const next: RequestInit = { ...init, credentials: sameOrigin ? "include" : init.credentials };
    if (sameOrigin && needsCsrf(method)) {
      next.headers = { ...(init.headers as Record<string, string>), ...csrfHeaders(method) };
    }
    const res = await original(input, next);
    if (sameOrigin && isUnauthenticated(res, method)) {
      goToLogin();
    }
    return res;
  };
}

/** Probe whether the browser already has a valid admin session — /account/profile is session-gated
 *  (200 authenticated, 302→login otherwise). */
export const SESSION_PROBE = `/realms/${ADMIN_REALM}/account/profile`;
export async function hasSession(): Promise<boolean> {
  try {
    const res = await window.fetch(SESSION_PROBE, { redirect: "manual" });
    return res.ok;
  } catch {
    return false;
  }
}
