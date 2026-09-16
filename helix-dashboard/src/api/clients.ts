/**
 * True when a string is (or embeds) a UUID — e.g. a bare UUID or a Dynamic-Client-Registration id like
 * `dcr-5bcd8361-…`. Used to keep machine-generated identifiers from ever surfacing as a UI name.
 */
export function looksLikeUuid(value: string | null | undefined): boolean {
  return !!value && /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(value);
}

/**
 * The human label for a client: its display name, else the clientId — but NEVER a raw UUID/`dcr-…`
 * identifier (those stay as the muted technical "Client ID" field only). Falls back to "Unnamed client".
 */
export function clientLabel(c: { name?: string | null; clientId?: string | null }): string {
  if (c.name && c.name.trim()) return c.name.trim();
  if (c.clientId && c.clientId.trim() && !looksLikeUuid(c.clientId)) return c.clientId.trim();
  return "Unnamed client";
}

/** An OAuth client from the E8.5-S3 Clients admin API. */
export interface Client {
  realmId: string;
  id: string;
  clientId: string;
  grantTypes: string[];
  redirectUris: string[];
  scopes: string[];
  /** Only present on create / regenerate. */
  secret: string | null;
  /** Per-client override of the subject (`sub`) source claim; `null` = inherit the realm default. */
  subjectClaim: string | null;
  /** Per-client login-flow override (named flow alias); `null` = inherit the realm's `browser` flow. */
  authFlowAlias: string | null;
  /** The parent Application (`realmId|name`) this client hangs below; `null` = standalone client. */
  applicationId: string | null;
  /** Display name; `null` falls back to the client ID. */
  name: string | null;
  /** Free-text description. */
  description: string | null;
  /** Where the browser may return after RP-initiated logout. */
  postLogoutRedirectUris: string[];
  /** Browser origins allowed to call this realm's endpoints cross-origin (CORS). */
  webOrigins: string[];
  /** Public client (SPA/native): no secret, PKCE required. */
  publicClient: boolean;
  /** Show the OAuth consent screen before issuing tokens. */
  consentRequired: boolean;
  displayOnConsentScreen: boolean;
  loginTheme: string | null;
  rootUrl: string | null;
  homeUrl: string | null;
  adminUrl: string | null;
  alwaysDisplayInConsole: boolean;
  /** Per-client access-token lifespan in seconds; null = realm default. */
  accessTokenLifespan: number | null;
  refreshTokenLifespan: number | null;
  /** ID-token signature algorithm (RS256/ES256…); null = RS256. */
  idTokenSignatureAlg: string | null;
  reuseRefreshTokens: boolean;
  /** Token-endpoint client auth: null/`CLIENT_SECRET_BASIC` (secret) or `PRIVATE_KEY_JWT` (signed JWT). */
  tokenEndpointAuthMethod: string | null;
  /** The client's JWKS URL — the server fetches it to verify `private_key_jwt` assertions. */
  jwksUrl: string | null;
  /** OIDC Back-Channel Logout: URL the server POSTs a signed `logout_token` to at logout; null = none. */
  backchannelLogoutUri: string | null;
  /** OIDC Front-Channel Logout: URL loaded in an iframe at logout; null = none. */
  frontchannelLogoutUri: string | null;
  /**
   * RFC 8707 Resource Indicators: allow-list of absolute resource URIs this client may request via the
   * `resource` parameter (sets the access-token `aud`). Empty = no allow-list → any valid resource accepted.
   */
  allowedResources: string[];
  /** FAPI / RFC 8705: bind access tokens to the client's mTLS certificate (`cnf.x5t#S256`). */
  x509CertificateBoundAccessTokens: boolean;
  /** FAPI / RFC 9101 (JAR): require the authorization request to be a signed Request Object. */
  requireSignedRequestObject: boolean;
  /** FAPI / JARM: JWT-secured authorization response mode (`jwt`/`query.jwt`/`fragment.jwt`/`form_post.jwt`); `null` = plain OAuth. */
  jarmResponseMode: string | null;
}

export interface ClientWrite {
  clientId: string;
  grantTypes: string[];
  redirectUris: string[];
  scopes: string[];
  /** `null`/omitted = inherit the realm default subject claim. */
  subjectClaim?: string | null;
  /** `null`/omitted = inherit the realm's default `browser` login flow. */
  authFlowAlias?: string | null;
  /** The parent Application (`realmId|name`); send the existing value to preserve the link on save. */
  applicationId?: string | null;
  name?: string | null;
  description?: string | null;
  postLogoutRedirectUris?: string[];
  webOrigins?: string[];
  publicClient?: boolean;
  consentRequired?: boolean;
  displayOnConsentScreen?: boolean;
  loginTheme?: string | null;
  rootUrl?: string | null;
  homeUrl?: string | null;
  adminUrl?: string | null;
  alwaysDisplayInConsole?: boolean;
  accessTokenLifespan?: number | null;
  refreshTokenLifespan?: number | null;
  idTokenSignatureAlg?: string | null;
  reuseRefreshTokens?: boolean;
  tokenEndpointAuthMethod?: string | null;
  jwksUrl?: string | null;
  backchannelLogoutUri?: string | null;
  frontchannelLogoutUri?: string | null;
  /** RFC 8707: allow-list of absolute resource URIs; omit/empty = no allow-list (accept any valid resource). */
  allowedResources?: string[];
  /** FAPI / RFC 8705: bind access tokens to the client's mTLS certificate (`cnf.x5t#S256`). */
  x509CertificateBoundAccessTokens?: boolean;
  /** FAPI / RFC 9101 (JAR): require the authorization request to be a signed Request Object. */
  requireSignedRequestObject?: boolean;
  /** FAPI / JARM: JWT-secured authorization response mode; `null`/omit = plain OAuth. */
  jarmResponseMode?: string | null;
}

export interface ClientApi {
  list(realmId: string): Promise<Client[]>;
  create(realmId: string, body: ClientWrite): Promise<Client>;
  update(realmId: string, id: string, body: ClientWrite): Promise<Client>;
  regenerate(realmId: string, id: string): Promise<Client>;
  /** Reveal the current secret (Credentials tab); returned client has `secret` populated. */
  reveal(realmId: string, id: string): Promise<Client>;
  remove(realmId: string, id: string): Promise<void>;
  /** RFC 8707 resource-indicator allow-list for this client (empty = any resource accepted). */
  getAllowedResources(realmId: string, clientId: string): Promise<string[]>;
  setAllowedResources(realmId: string, clientId: string, resources: string[]): Promise<void>;
}

/** HTTP-backed client for the E8.5-S3 clients admin REST API. */
export function createClientHttpClient(baseUrl = ""): ClientApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, id?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/clients${id ? `/${encodeURIComponent(id)}` : ""}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId) => fetch(url(realmId)).then(json),
    create: (realmId, body) =>
      fetch(url(realmId), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    update: (realmId, id, body) =>
      fetch(url(realmId, id), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    regenerate: (realmId, id) => fetch(`${url(realmId, id)}/secret`, { method: "POST" }).then(json),
    reveal: (realmId, id) => fetch(`${url(realmId, id)}/secret`).then(json),
    remove: (realmId, id) => fetch(url(realmId, id), { method: "DELETE" }).then(json).then(() => undefined),
    getAllowedResources: (realmId, clientId) => fetch(`${url(realmId, clientId)}/allowed-resources`).then(json).then((r) => r ?? []),
    setAllowedResources: (realmId, clientId, resources) =>
      fetch(`${url(realmId, clientId)}/allowed-resources`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ resources }) }).then(json).then(() => undefined),
  };
}
