/** One client touched within a session (SSO P7 / Sessions v2). */
export interface SessionClient {
  clientId: string;
  grantType: string;
  scopes: string[];
  issuedAt: string | null;
  expiresAt: string | null;
}

/** The kind of identity behind a session/token. */
export type IdentityType = "USER" | "AGENT" | "SERVICE_ACCOUNT" | "WORKLOAD";

/** A unified active identity — an SSO session (user/agent) or a service-account token (Sessions v2). */
export interface IdentitySession {
  id: string;
  identityType: IdentityType;
  principalName: string;
  displayName: string;
  realm: string;
  issuedAt: string | null;
  expiresAt: string | null;
  revokeMode: "SLO" | "TOKEN";
  clients: SessionClient[];
}

/** Build the `?q=&type=` query string for the sessions list endpoint; empty when no filters. */
export function buildSessionsQuery(opts: { q?: string; type?: string }): string {
  const p = new URLSearchParams();
  if (opts.q && opts.q.trim()) p.set("q", opts.q.trim());
  if (opts.type && opts.type.trim()) p.set("type", opts.type.trim());
  const s = p.toString();
  return s ? `?${s}` : "";
}

export interface SessionApi {
  /** Active identities for the realm (user / agent / service account), optionally filtered server-side. */
  list(realmId: string, opts?: { q?: string; type?: string }): Promise<IdentitySession[]>;
  /** Revoke one identity — SLO for a session, token revoke for a service account (dispatched server-side). */
  revoke(realmId: string, id: string): Promise<void>;
}

/** HTTP-backed client for the Sessions admin REST API. */
export function createSessionHttpClient(baseUrl = ""): SessionApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}/sessions`;

  const ok = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId, opts = {}) => fetch(root(realmId) + buildSessionsQuery(opts)).then(ok),
    revoke: (realmId, id) =>
      fetch(`${root(realmId)}/${encodeURIComponent(id)}`, { method: "DELETE" }).then(ok).then(() => undefined),
  };
}
