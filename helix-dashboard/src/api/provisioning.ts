/** A realm's provisioning settings from the E11 Provisioning admin API (SCIM token + DCR policy). */
export interface ProvisioningConfig {
  realmId: string;
  scimTokenSet: boolean;
  dcrOpen: boolean;
}

/** Save payload. {@code dcrOpen} null leaves the policy unchanged; the SCIM-token flags are exclusive. */
export interface ProvisioningSaveRequest {
  dcrOpen: boolean | null;
  rotateScimToken: boolean;
  clearScimToken: boolean;
}

/** Save result; {@code newScimToken} is the freshly-generated SCIM token, present once when rotated. */
export interface ProvisioningSaveResult {
  config: ProvisioningConfig;
  newScimToken: string | null;
}

export interface InitialAccessTokenResult {
  initialAccessToken: string;
}

export interface ProvisioningApi {
  get(realmId: string): Promise<ProvisioningConfig>;
  save(realmId: string, body: ProvisioningSaveRequest): Promise<ProvisioningSaveResult>;
  issueInitialAccessToken(realmId: string): Promise<InitialAccessTokenResult>;
}

/** HTTP-backed client for the E11 provisioning admin REST API. */
export function createProvisioningHttpClient(baseUrl = ""): ProvisioningApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}/provisioning`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  };

  return {
    get: (realmId) => fetch(root(realmId)).then(json),
    save: (realmId, body) =>
      fetch(root(realmId), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    issueInitialAccessToken: (realmId) =>
      fetch(`${root(realmId)}/initial-access-tokens`, { method: "POST" }).then(json),
  };
}
