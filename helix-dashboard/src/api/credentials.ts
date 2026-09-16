/** One enrolled authentication factor for a user, as the E8.5 credentials admin API returns it. */
export interface CredentialSummary {
  /** Factor family: "passkey" | "device" | "totp" | "hotp" | "recovery-code". */
  type: string;
  /** Revocation handle within the type (credentialId / deviceId / a fixed token). */
  id: string;
  label: string;
  detail: string;
  createdAt: number | null;
  lastUsedAt: number | null;
  revocable: boolean;
}

export interface CredentialApi {
  list(realmId: string, userId: string): Promise<CredentialSummary[]>;
  revoke(realmId: string, userId: string, type: string, id: string): Promise<void>;
}

/** HTTP-backed client for the E8.5 per-user credentials admin REST API. */
export function createCredentialHttpClient(baseUrl = ""): CredentialApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string, userId: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/users/${encodeURIComponent(userId)}/credentials`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId, userId) => fetch(root(realmId, userId)).then(json),
    revoke: (realmId, userId, type, id) =>
      fetch(`${root(realmId, userId)}/${encodeURIComponent(type)}/${encodeURIComponent(id)}`, { method: "DELETE" })
        .then(json)
        .then(() => undefined),
  };
}

/** In-memory client for stories/tests. */
export function createCredentialMemoryClient(seed: Record<string, CredentialSummary[]> = {}): CredentialApi {
  const store = new Map<string, CredentialSummary[]>(Object.entries(seed));
  return {
    list: async (_realmId, userId) => store.get(userId) ?? [],
    revoke: async (_realmId, userId, type, id) => {
      const next = (store.get(userId) ?? []).filter((c) => !(c.type === type && c.id === id));
      store.set(userId, next);
    },
  };
}

/** Display metadata for each factor family — title + one-line description + ordering. */
export interface FactorKind {
  type: string;
  title: string;
  description: string;
}

/** The factor families in the order the screen presents them (strongest/phishing-resistant first). */
export const FACTOR_KINDS: FactorKind[] = [
  { type: "passkey", title: "Passkeys", description: "Phishing-resistant FIDO2 credentials bound to this account." },
  { type: "device", title: "Trusted devices", description: "Enrolled mobile devices with a hardware-backed signing key." },
  { type: "totp", title: "Authenticator app (TOTP)", description: "Time-based one-time-password generators." },
  { type: "hotp", title: "Authenticator app (HOTP)", description: "Counter-based one-time-password generators." },
  { type: "recovery-code", title: "Recovery codes", description: "Single-use backup codes for account recovery." },
];

export interface FactorGroup {
  kind: FactorKind;
  items: CredentialSummary[];
}

/**
 * Groups a flat credential list into the fixed factor families, preserving {@link FACTOR_KINDS} order
 * and dropping empty groups. Any factor of an unknown type is collected under a trailing "Other" group
 * so nothing is ever silently hidden.
 */
export function groupCredentials(creds: CredentialSummary[]): FactorGroup[] {
  const groups: FactorGroup[] = [];
  for (const kind of FACTOR_KINDS) {
    const items = creds.filter((c) => c.type === kind.type);
    if (items.length > 0) groups.push({ kind, items });
  }
  const known = new Set(FACTOR_KINDS.map((k) => k.type));
  const others = creds.filter((c) => !known.has(c.type));
  if (others.length > 0) {
    groups.push({ kind: { type: "other", title: "Other factors", description: "Additional enrolled credentials." }, items: others });
  }
  return groups;
}
