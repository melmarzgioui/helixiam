/** One node of an authentication flow from the E8.5-S4 Auth-flow editor API. */
export interface FlowExecution {
  executionId: string;
  parentId: string | null;
  /** null for a sub-flow node (a node that only groups children). */
  authenticatorId: string | null;
  requirement: string;
  condition: boolean;
  priority: number;
  /** Per-execution admin config (e.g. an idp-redirect step's providerAlias + mode); absent for most steps. */
  config?: Record<string, string>;
}

/** One configurable setting an authenticator declares, rendered generically by the editor. */
export interface ConfigProperty {
  key: string;
  label: string;
  type: "STRING" | "BOOLEAN" | "INTEGER" | "SECRET" | "SELECT";
  required: boolean;
  defaultValue: string | null;
  options: string[];
}

export interface FlowDefinition {
  realmId: string;
  alias: string;
  builtIn: boolean;
  executions: FlowExecution[];
}

/** An installed authenticator the editor can drop into a flow. */
export interface AuthenticatorCatalogEntry {
  id: string;
  displayName: string;
  factorClass: string;
  levelOfAssurance: number;
  /**
   * Backend-declared editor grouping: "METHOD" (a sign-in step the user performs) or
   * "CONDITION" (a predicate that gates a sub-flow). The editor uses this instead of guessing
   * from factorClass/levelOfAssurance. May be absent when talking to an older backend.
   */
  category?: "METHOD" | "CONDITION";
  /** The per-step config the editor renders (empty for steps with no settings). */
  configSchema?: ConfigProperty[];
}

/**
 * Is this catalogue entry a flow *condition* (vs a sign-in method)? Reads the backend-declared
 * {@link AuthenticatorCatalogEntry.category}; falls back to the legacy factorClass/LoA heuristic
 * only when an older backend omits it.
 */
export const isConditionCatalogEntry = (cat?: AuthenticatorCatalogEntry): boolean => {
  if (!cat) return false;
  if (cat.category) return cat.category === "CONDITION";
  return cat.factorClass === "NONE" && cat.levelOfAssurance === 0;
};

/** A realm flow in the editor's flow picker (named-flows API). */
export interface FlowSummary {
  realmId: string;
  alias: string;
  /** The built-in `browser` flow cannot be renamed or deleted. */
  builtIn: boolean;
}

export interface FlowApi {
  get(realmId: string): Promise<FlowDefinition>;
  save(realmId: string, executions: FlowExecution[]): Promise<FlowDefinition>;
  catalog(realmId: string): Promise<AuthenticatorCatalogEntry[]>;
  /** Named flows (full parity): every flow in the realm. */
  list(realmId: string): Promise<FlowSummary[]>;
  getByAlias(realmId: string, alias: string): Promise<FlowDefinition>;
  saveByAlias(realmId: string, alias: string, executions: FlowExecution[]): Promise<FlowDefinition>;
  create(realmId: string, alias: string, copyFromAlias?: string | null): Promise<FlowSummary>;
  rename(realmId: string, alias: string, newAlias: string): Promise<FlowSummary>;
  remove(realmId: string, alias: string): Promise<void>;
}

/** HTTP-backed client for the E8.5-S4 auth-flow admin REST API. */
export function createFlowHttpClient(baseUrl = ""): FlowApi {
  const base = baseUrl.replace(/\/$/, "");
  const realmBase = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}`;
  const flowUrl = (realmId: string) => `${realmBase(realmId)}/flow`;
  const flowsUrl = (realmId: string, alias?: string) =>
    `${realmBase(realmId)}/flows${alias ? `/${encodeURIComponent(alias)}` : ""}`;
  const catalogUrl = (realmId: string) => `${realmBase(realmId)}/authenticators`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };
  const body = (payload: unknown) => ({
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  return {
    get: (realmId) => fetch(flowUrl(realmId)).then(json),
    save: (realmId, executions) =>
      fetch(flowUrl(realmId), { method: "PUT", ...body({ executions }) }).then(json),
    catalog: (realmId) => fetch(catalogUrl(realmId)).then(json),
    list: (realmId) => fetch(flowsUrl(realmId)).then(json),
    getByAlias: (realmId, alias) => fetch(flowsUrl(realmId, alias)).then(json),
    saveByAlias: (realmId, alias, executions) =>
      fetch(flowsUrl(realmId, alias), { method: "PUT", ...body({ executions }) }).then(json),
    create: (realmId, alias, copyFromAlias = null) =>
      fetch(flowsUrl(realmId), { method: "POST", ...body({ alias, copyFromAlias }) }).then(json),
    rename: (realmId, alias, newAlias) =>
      fetch(flowsUrl(realmId, alias), { method: "PATCH", ...body({ alias: newAlias }) }).then(json),
    remove: (realmId, alias) => fetch(flowsUrl(realmId, alias), { method: "DELETE" }).then(json).then(() => undefined),
  };
}
