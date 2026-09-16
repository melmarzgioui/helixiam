/**
 * Helix IAM (6) Self-service Account: the END-USER "my account" API client. Unlike the admin clients (which
 * address a user by id), every call here is keyed off the authenticated principal server-side — the URLs
 * carry no userId. Served under {@code /realms/{realm}/account/**}; the browser is already signed in via the
 * realm's OIDC, so requests go same-origin with the session cookie ({@code credentials: "include"}).
 */
import { csrfHeader } from "./csrf";

/** The signed-in user's profile (username is read-only). Mirrors the backend UserAdminDto. */
export interface AccountProfile {
  realmId: string;
  userId: string;
  username: string;
  email: string | null;
  enabled: boolean;
  locked: boolean;
  mfaEnabled: boolean;
  roles: string[];
  attributes: Record<string, string>;
  createdAt: number | null;
}

/** One enrolled authentication factor (passkey / device / totp / hotp / recovery-code). */
export interface AccountCredential {
  type: string;
  id: string;
  label: string;
  detail: string;
  createdAt: number | null;
  lastUsedAt: number | null;
  revocable: boolean;
}

/** One client touched within an SSO session. */
export interface AccountSessionClient {
  clientId: string;
  grantType: string;
  scopes: string[];
  issuedAt: string | null;
  expiresAt: string | null;
}

/** One of the caller's own SSO sessions (a browser login, clients rolled up). */
export interface AccountSession {
  ssoSessionId: string;
  principalName: string;
  realm: string;
  issuedAt: string | null;
  expiresAt: string | null;
  clients: AccountSessionClient[];
}

/** One application the caller has authorized (a consent). */
export interface AccountConsent {
  clientId: string;
  scopes: string[];
  grantedAt: string | null;
}

/** GDPR Art. 7: one entry in the caller's consent ledger (a grant, possibly later withdrawn). */
export interface GdprConsentRecord {
  id: string;
  realmId: string;
  userId: string;
  clientId: string;
  scopes: string[];
  grantedAt: number | null;
  withdrawnAt: number | null;
}

/** GDPR Art. 15/20: the caller's full data export. Open-ended (schema-tagged); rendered/downloaded as JSON. */
export interface GdprExport {
  generatedAt: number | null;
  schema: string;
  realmId: string;
  userId: string;
  profile: Record<string, unknown> | null;
  attributes: Record<string, string>;
  roles: string[];
  realmMemberships: unknown[];
  organizations: unknown[];
  credentials: unknown[];
  federatedLinks: unknown[];
  consents: GdprConsentRecord[];
  loginEvents: unknown[];
}

/** B9: one identity provider the caller's account is linked through (a "connected account"). */
export interface AccountIdentity {
  idpAlias: string;
  externalSubject: string;
  linkedAt: number | null;
}

export interface AccountApi {
  getProfile(): Promise<AccountProfile>;
  updateProfile(patch: { email: string | null; attributes: Record<string, string> }): Promise<AccountProfile>;
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  listCredentials(): Promise<AccountCredential[]>;
  revokeCredential(type: string, id: string): Promise<void>;
  listSessions(): Promise<AccountSession[]>;
  revokeSession(ssoSessionId: string): Promise<void>;
  listConsents(): Promise<AccountConsent[]>;
  revokeConsent(clientId: string): Promise<void>;
  // B9: connected accounts (federated identities) — list + disconnect.
  listIdentities(): Promise<AccountIdentity[]>;
  unlinkIdentity(alias: string): Promise<void>;
  // GDPR / Privacy (self-service): export own data, read + withdraw own consent ledger.
  gdprExport(): Promise<GdprExport>;
  gdprConsents(): Promise<GdprConsentRecord[]>;
  gdprWithdrawConsent(clientId: string): Promise<void>;
}

/** A 4xx/5xx carrying the server status, so the UI can show a precise message (e.g. 400 on wrong password). */
export class AccountApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "AccountApiError";
  }
}

/**
 * HTTP-backed client. {@code realm} is required (the surface is realm-scoped, like the rest of Helix). The
 * base defaults to same-origin; set VITE_API_BASE to point the dev build at the auth server.
 */
export function createAccountHttpClient(realm: string, baseUrl = ""): AccountApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = `${base}/realms/${encodeURIComponent(realm)}/account`;

  const send = async (path: string, init?: RequestInit) => {
    // #322: session-cookie writes need the CSRF token from the JS-readable XSRF-TOKEN cookie.
    const cookies = typeof document !== "undefined" ? document.cookie : "";
    const headers = {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...csrfHeader(init?.method, cookies),
    };
    const res = await fetch(`${root}${path}`, {
      credentials: "include",
      ...init,
      headers,
    });
    if (!res.ok) {
      throw new AccountApiError(res.status, `${res.status} ${res.statusText}`);
    }
    return res.status === 204 ? null : res.json();
  };

  return {
    getProfile: () => send("/profile"),
    updateProfile: (patch) => send("/profile", { method: "PUT", body: JSON.stringify(patch) }),
    changePassword: (currentPassword, newPassword) =>
      send("/password", { method: "PUT", body: JSON.stringify({ currentPassword, newPassword }) }).then(() => undefined),
    listCredentials: () => send("/credentials"),
    revokeCredential: (type, id) =>
      send(`/credentials/${encodeURIComponent(type)}/${encodeURIComponent(id)}`, { method: "DELETE" }).then(() => undefined),
    listSessions: () => send("/sessions"),
    revokeSession: (ssoSessionId) =>
      send(`/sessions/${encodeURIComponent(ssoSessionId)}`, { method: "DELETE" }).then(() => undefined),
    listConsents: () => send("/consents"),
    revokeConsent: (clientId) =>
      send(`/consents/${encodeURIComponent(clientId)}`, { method: "DELETE" }).then(() => undefined),
    listIdentities: () => send("/identities"),
    unlinkIdentity: (alias) =>
      send(`/identities/${encodeURIComponent(alias)}`, { method: "DELETE" }).then(() => undefined),
    gdprExport: () => send("/gdpr/export"),
    gdprConsents: () => send("/gdpr/consents"),
    gdprWithdrawConsent: (clientId) =>
      send(`/gdpr/consents/${encodeURIComponent(clientId)}`, { method: "DELETE" }).then(() => undefined),
  };
}
