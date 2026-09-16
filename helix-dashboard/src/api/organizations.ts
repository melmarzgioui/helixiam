/** An Organization (B2B tenant grouping of users) from the Organizations admin API. */
export interface Organization {
  realmId: string;
  orgId: string;
  /** Stable identifier, unique per realm. */
  name: string;
  /** Human-friendly label; null/blank = fall back to `name`. */
  displayName: string | null;
  /** Email domains used for domain-based membership. */
  domains: string[];
  enabled: boolean;
  memberCount: number;
  createdAt: number | null;
}

export interface OrganizationWrite {
  name: string;
  displayName?: string | null;
  domains?: string[];
  enabled?: boolean;
}

/** A member of an organization, with their role within the org. */
export interface OrgMember {
  userId: string;
  username: string;
  role: string;
}

export interface OrganizationApi {
  list(realmId: string): Promise<Organization[]>;
  get(realmId: string, orgId: string): Promise<Organization>;
  create(realmId: string, body: OrganizationWrite): Promise<Organization>;
  update(realmId: string, orgId: string, body: OrganizationWrite): Promise<Organization>;
  remove(realmId: string, orgId: string): Promise<void>;
  members(realmId: string, orgId: string): Promise<OrgMember[]>;
  addMember(realmId: string, orgId: string, userId: string, role?: string): Promise<void>;
  removeMember(realmId: string, orgId: string, userId: string): Promise<void>;
}

/** The label to show for an org: its human display name, falling back to the stable id when unset. */
export function organizationLabel(org: Pick<Organization, "name" | "displayName">): string {
  return org.displayName && org.displayName.trim() ? org.displayName : org.name;
}

/** Parse a comma/whitespace/newline-separated domains string into a clean, lowercased, de-duped list. */
export function parseDomains(input: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of input.split(/[\s,]+/)) {
    const d = raw.trim().toLowerCase();
    if (d && !seen.has(d)) {
      seen.add(d);
      out.push(d);
    }
  }
  return out;
}

/** Field-level validation for the create/edit-organization form. Pure so it can be unit-tested. */
export function validateOrganization(w: OrganizationWrite): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!w.name?.trim()) {
    errors.name = "Name is required.";
  } else if (!/^[\w .@:/-]+$/.test(w.name.trim())) {
    errors.name = "Use letters, numbers, spaces or . _ - @ : /";
  }
  const bad = (w.domains ?? []).find((d) => !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d));
  if (bad) {
    errors.domains = `“${bad}” is not a valid domain.`;
  }
  return errors;
}

/** HTTP-backed client for the Organizations admin REST API. */
export function createOrganizationHttpClient(baseUrl = ""): OrganizationApi {
  const base = baseUrl.replace(/\/$/, "");
  const o = (realmId: string, orgId?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/organizations${orgId ? `/${encodeURIComponent(orgId)}` : ""}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };
  const send = (url: string, method: string, body?: unknown) =>
    fetch(url, body === undefined
      ? { method }
      : { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json);

  return {
    list: (realmId) => send(o(realmId), "GET"),
    get: (realmId, orgId) => send(o(realmId, orgId), "GET"),
    create: (realmId, body) => send(o(realmId), "POST", body),
    update: (realmId, orgId, body) => send(o(realmId, orgId), "PUT", body),
    remove: (realmId, orgId) => send(o(realmId, orgId), "DELETE").then(() => undefined),
    members: (realmId, orgId) => send(`${o(realmId, orgId)}/members`, "GET"),
    addMember: (realmId, orgId, userId, role) =>
      send(`${o(realmId, orgId)}/members/${encodeURIComponent(userId)}`, "PUT", role ? { role } : {}).then(() => undefined),
    removeMember: (realmId, orgId, userId) =>
      send(`${o(realmId, orgId)}/members/${encodeURIComponent(userId)}`, "DELETE").then(() => undefined),
  };
}
