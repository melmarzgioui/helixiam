/** The OIDC/OAuth2 endpoint URLs a relying party integrates against (E8.5 — the "Installation" view). */
export interface OidcEndpoints {
  issuer: string;
  discovery: string;
  authorization: string;
  token: string;
  deviceAuthorization: string;
  userInfo: string;
  jwks: string;
  endSession: string;
  introspection: string;
  revocation: string;
}

/** Fetches the realm's OIDC endpoint URLs (mirrors its discovery document). */
export function fetchOidcEndpoints(realmId: string, baseUrl = ""): Promise<OidcEndpoints> {
  const base = baseUrl.replace(/\/$/, "");
  return fetch(`${base}/admin/realms/${encodeURIComponent(realmId)}/endpoints`).then((res) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  });
}
