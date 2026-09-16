/**
 * Helix IAM WIF: a per-realm workload identity credential — a keyless trust policy binding an external
 * OIDC token's (issuer, subject, audience) to a Helix client identity. No field is secret, so everything
 * round-trips to the console unmasked.
 */
export interface WorkloadIdentityCredential {
  id: string;
  realmId: string;
  name: string;
  issuer: string;
  /** Explicit JWKS URL; blank ⇒ discovered from the issuer's OIDC metadata. */
  jwksUri: string | null;
  subject: string;
  audience: string;
  /** The Helix identity a matching workload acts as (becomes the minted token's `sub`). */
  clientId: string;
  /** Space-delimited scopes granted to the minted token. */
  scopes: string | null;
  enabled: boolean;
  createdAt: number | null;
}

export interface WorkloadIdentityWrite {
  name: string;
  issuer: string;
  jwksUri?: string | null;
  subject: string;
  audience: string;
  clientId: string;
  scopes?: string | null;
  enabled?: boolean;
}

export interface WorkloadIdentityApi {
  list(realmId: string): Promise<WorkloadIdentityCredential[]>;
  create(realmId: string, body: WorkloadIdentityWrite): Promise<WorkloadIdentityCredential>;
  update(realmId: string, id: string, body: WorkloadIdentityWrite): Promise<WorkloadIdentityCredential>;
  remove(realmId: string, id: string): Promise<void>;
}

/**
 * Pure validator: name, issuer (absolute http(s)), subject, audience, and client identity are required;
 * a JWKS URL, when given, must be absolute http(s) (blank is allowed — it's discovered). Returns the
 * keys of the failing fields.
 */
export function validateWorkloadIdentity(w: WorkloadIdentityWrite): string[] {
  const errors: string[] = [];
  const blank = (s: string | null | undefined) => !(s ?? "").trim();
  if (blank(w.name)) errors.push("name");
  if (!/^https?:\/\/.+/.test((w.issuer ?? "").trim())) errors.push("issuer");
  if (blank(w.subject)) errors.push("subject");
  if (blank(w.audience)) errors.push("audience");
  if (blank(w.clientId)) errors.push("clientId");
  if ((w.jwksUri ?? "").trim() && !/^https?:\/\/.+/.test((w.jwksUri ?? "").trim())) errors.push("jwksUri");
  return errors;
}

function json(res: Response) {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.status === 204 ? null : res.json();
}
const send = (url: string, method: string, body?: unknown) =>
  fetch(url, body === undefined
    ? { method }
    : { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json);

/** HTTP-backed client for the WIF admin REST API. */
export function createWorkloadIdentityHttpClient(baseUrl = ""): WorkloadIdentityApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, id?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/workload-identity${id ? `/${encodeURIComponent(id)}` : ""}`;
  return {
    list: (realmId) => send(url(realmId), "GET"),
    create: (realmId, body) => send(url(realmId), "POST", body),
    update: (realmId, id, body) => send(url(realmId, id), "PUT", body),
    remove: (realmId, id) => send(url(realmId, id), "DELETE").then(() => undefined),
  };
}
