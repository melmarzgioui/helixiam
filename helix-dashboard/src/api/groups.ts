/** A group from the E8.5-S4 Groups admin API. */
export interface Group {
  realmId: string;
  groupId: string;
  name: string;
  parentId: string | null;
  memberCount: number;
  roleNames: string[];
}

/** A member of a group. */
export interface GroupMember {
  userId: string;
  username: string;
}

/** A realm role mapped onto a group. */
export interface GroupRole {
  realmId: string;
  roleId: string;
  name: string;
}

export interface GroupApi {
  list(realmId: string): Promise<Group[]>;
  create(realmId: string, name: string, parentId: string | null): Promise<Group>;
  rename(realmId: string, groupId: string, name: string, parentId: string | null): Promise<Group>;
  remove(realmId: string, groupId: string): Promise<void>;
  members(realmId: string, groupId: string): Promise<GroupMember[]>;
  addMember(realmId: string, groupId: string, userId: string): Promise<void>;
  removeMember(realmId: string, groupId: string, userId: string): Promise<void>;
  roles(realmId: string, groupId: string): Promise<GroupRole[]>;
  assignRole(realmId: string, groupId: string, roleId: string): Promise<void>;
  unassignRole(realmId: string, groupId: string, roleId: string): Promise<void>;
}

/** HTTP-backed client for the E8.5-S4 groups admin REST API. */
export function createGroupHttpClient(baseUrl = ""): GroupApi {
  const base = baseUrl.replace(/\/$/, "");
  const g = (realmId: string, groupId?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/groups${groupId ? `/${encodeURIComponent(groupId)}` : ""}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };
  const send = (url: string, method: string, body?: unknown) =>
    fetch(url, body === undefined
      ? { method }
      : { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json);

  return {
    list: (realmId) => send(g(realmId), "GET"),
    create: (realmId, name, parentId) => send(g(realmId), "POST", { name, parentId }),
    rename: (realmId, groupId, name, parentId) => send(g(realmId, groupId), "PUT", { name, parentId }),
    remove: (realmId, groupId) => send(g(realmId, groupId), "DELETE").then(() => undefined),
    members: (realmId, groupId) => send(`${g(realmId, groupId)}/members`, "GET"),
    addMember: (realmId, groupId, userId) => send(`${g(realmId, groupId)}/members/${encodeURIComponent(userId)}`, "PUT").then(() => undefined),
    removeMember: (realmId, groupId, userId) => send(`${g(realmId, groupId)}/members/${encodeURIComponent(userId)}`, "DELETE").then(() => undefined),
    roles: (realmId, groupId) => send(`${g(realmId, groupId)}/roles`, "GET"),
    assignRole: (realmId, groupId, roleId) => send(`${g(realmId, groupId)}/roles/${encodeURIComponent(roleId)}`, "PUT").then(() => undefined),
    unassignRole: (realmId, groupId, roleId) => send(`${g(realmId, groupId)}/roles/${encodeURIComponent(roleId)}`, "DELETE").then(() => undefined),
  };
}
