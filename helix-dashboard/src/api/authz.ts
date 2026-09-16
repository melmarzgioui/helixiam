/** Wave 6: Authorization Services (UMA-style fine-grained authorization) admin API. */
export interface AuthzServer { realmId: string; clientId: string; enabled: boolean; decisionStrategy: string; }
export interface AuthzScope { id: string; realmId: string; clientId: string; name: string; }
export interface AuthzResource { id: string; realmId: string; clientId: string; name: string; uris: string[]; scopes: string[]; }
export interface AuthzPolicy { id: string; realmId: string; clientId: string; name: string; type: string; logic: string; roles: string[]; }
export interface AuthzPermission {
  id: string; realmId: string; clientId: string; name: string; type: string;
  resourceName: string | null; scopeName: string | null; policies: string[]; decisionStrategy: string;
}
export interface AuthzEvalResult { granted: boolean; grantingPermissions: string[]; denyingPermissions: string[]; }

export interface AuthzApi {
  getSettings(realm: string, clientId: string): Promise<AuthzServer>;
  saveSettings(realm: string, clientId: string, enabled: boolean, decisionStrategy: string): Promise<AuthzServer>;
  listScopes(realm: string, clientId: string): Promise<AuthzScope[]>;
  createScope(realm: string, clientId: string, name: string): Promise<AuthzScope>;
  removeScope(realm: string, clientId: string, name: string): Promise<void>;
  listResources(realm: string, clientId: string): Promise<AuthzResource[]>;
  createResource(realm: string, clientId: string, name: string, uris: string[], scopes: string[]): Promise<AuthzResource>;
  removeResource(realm: string, clientId: string, name: string): Promise<void>;
  listPolicies(realm: string, clientId: string): Promise<AuthzPolicy[]>;
  createPolicy(realm: string, clientId: string, name: string, logic: string, roles: string[]): Promise<AuthzPolicy>;
  removePolicy(realm: string, clientId: string, name: string): Promise<void>;
  listPermissions(realm: string, clientId: string): Promise<AuthzPermission[]>;
  createPermission(realm: string, clientId: string, body: { name: string; type: string; resourceName: string | null; scopeName: string | null; policies: string[]; decisionStrategy: string }): Promise<AuthzPermission>;
  removePermission(realm: string, clientId: string, name: string): Promise<void>;
  evaluate(realm: string, clientId: string, body: { username: string | null; roles: string[]; resourceName: string | null; scopeName: string | null }): Promise<AuthzEvalResult>;
}

export function createAuthzHttpClient(baseUrl = ""): AuthzApi {
  const base = baseUrl.replace(/\/$/, "");
  const u = (realm: string, clientId: string, sub: string) =>
    `${base}/admin/realms/${encodeURIComponent(realm)}/clients/${encodeURIComponent(clientId)}/authz${sub}`;
  const json = async (res: Response) => { if (!res.ok) throw new Error(`${res.status} ${res.statusText}`); return res.status === 204 ? null : res.json(); };
  const ok = (res: Response) => { if (!res.ok) throw new Error(`${res.status} ${res.statusText}`); };
  const post = (url: string, body: unknown) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  return {
    getSettings: (r, c) => fetch(u(r, c, "/settings")).then(json),
    saveSettings: (r, c, enabled, decisionStrategy) => fetch(u(r, c, "/settings"), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled, decisionStrategy }) }).then(json),
    listScopes: (r, c) => fetch(u(r, c, "/scopes")).then(json),
    createScope: (r, c, name) => post(u(r, c, "/scopes"), { name }).then(json),
    removeScope: (r, c, name) => fetch(u(r, c, `/scopes/${encodeURIComponent(name)}`), { method: "DELETE" }).then(ok),
    listResources: (r, c) => fetch(u(r, c, "/resources")).then(json),
    createResource: (r, c, name, uris, scopes) => post(u(r, c, "/resources"), { name, uris, scopes }).then(json),
    removeResource: (r, c, name) => fetch(u(r, c, `/resources/${encodeURIComponent(name)}`), { method: "DELETE" }).then(ok),
    listPolicies: (r, c) => fetch(u(r, c, "/policies")).then(json),
    createPolicy: (r, c, name, logic, roles) => post(u(r, c, "/policies"), { name, type: "ROLE", logic, roles }).then(json),
    removePolicy: (r, c, name) => fetch(u(r, c, `/policies/${encodeURIComponent(name)}`), { method: "DELETE" }).then(ok),
    listPermissions: (r, c) => fetch(u(r, c, "/permissions")).then(json),
    createPermission: (r, c, body) => post(u(r, c, "/permissions"), body).then(json),
    removePermission: (r, c, name) => fetch(u(r, c, `/permissions/${encodeURIComponent(name)}`), { method: "DELETE" }).then(ok),
    evaluate: (r, c, body) => post(u(r, c, "/evaluate"), body).then(json),
  };
}
