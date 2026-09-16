/** A role defined on a client (Wave 4). */
export interface ClientRole {
  roleId: string;
  realmId: string;
  clientId: string;
  name: string;
  description: string | null;
}

/** A role granted to a client's service account (Wave 4). */
export interface ServiceAccountRole {
  id: string;
  realmId: string;
  clientId: string;
  roleName: string;
  /** `REALM` or `CLIENT`. */
  roleType: string;
  roleClientId: string | null;
}

export interface ClientRoleApi {
  listRoles(realmId: string, clientId: string): Promise<ClientRole[]>;
  createRole(realmId: string, clientId: string, name: string, description: string | null): Promise<ClientRole>;
  removeRole(realmId: string, clientId: string, name: string): Promise<void>;
  listServiceAccountRoles(realmId: string, clientId: string): Promise<ServiceAccountRole[]>;
  assignServiceAccountRole(realmId: string, clientId: string, roleName: string, roleType: string, roleClientId: string | null): Promise<ServiceAccountRole>;
  unassignServiceAccountRole(realmId: string, clientId: string, roleName: string, roleType: string): Promise<void>;
}

/** HTTP-backed client for the Wave 4 client-roles + service-account-roles REST API. */
export function createClientRoleHttpClient(baseUrl = ""): ClientRoleApi {
  const base = baseUrl.replace(/\/$/, "");
  const client = (realmId: string, clientId: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/clients/${encodeURIComponent(clientId)}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };
  const ok = (res: Response) => { if (!res.ok) throw new Error(`${res.status} ${res.statusText}`); };

  return {
    listRoles: (realmId, clientId) => fetch(`${client(realmId, clientId)}/roles`).then(json),
    createRole: (realmId, clientId, name, description) =>
      fetch(`${client(realmId, clientId)}/roles`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, description }) }).then(json),
    removeRole: (realmId, clientId, name) =>
      fetch(`${client(realmId, clientId)}/roles/${encodeURIComponent(name)}`, { method: "DELETE" }).then(ok),
    listServiceAccountRoles: (realmId, clientId) => fetch(`${client(realmId, clientId)}/service-account/roles`).then(json),
    assignServiceAccountRole: (realmId, clientId, roleName, roleType, roleClientId) =>
      fetch(`${client(realmId, clientId)}/service-account/roles`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ roleName, roleType, roleClientId }) }).then(json),
    unassignServiceAccountRole: (realmId, clientId, roleName, roleType) =>
      fetch(`${client(realmId, clientId)}/service-account/roles?roleName=${encodeURIComponent(roleName)}&roleType=${encodeURIComponent(roleType)}`, { method: "DELETE" }).then(ok),
  };
}
