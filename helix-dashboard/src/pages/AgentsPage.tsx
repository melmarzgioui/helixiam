import React from "react";
import { Page, PageHeader, PageBody, PageToolbar, Section } from "../components/Page";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Badge, BadgeTone } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Drawer } from "../components/Drawer";
import { DetailList, Detail } from "../components/DetailList";
import { Toast, ToastTone } from "../components/Toast";
import { FormField, Input, Select } from "../components/FormField";
import { Combobox, ComboOption } from "../components/Combobox";
import { MultiCombobox } from "../components/MultiCombobox";
import { RowMenu, RowMenuItem } from "../components/RowMenu";
import { Agent, AgentApi, AgentWrite, AgentOwnerReview, OwnerStatus, agentStats, ownerIssueCount, ownerStatusById, paginate, parseCsv, validateAgent } from "../api/agents";
import { UserSummary } from "../api/users";
import { Client } from "../api/clients";
import { Role } from "../api/roles";
import { ClientRole } from "../api/clientRoles";
import { useT } from "../i18n/LocaleContext";

export interface AgentsPageProps {
  api: AgentApi;
  realmId: string;
  /** When set (Application detail tab), scope the list to this client and pre-bind new agents to it. */
  boundClientId?: string;
  /** Render without the full page header (when embedded in the Application detail tab). */
  embedded?: boolean;
  /** Optional — populates the Owner picker with the realm's users (searchable). */
  userApi?: { list(realmId: string): Promise<UserSummary[]> };
  /** Optional — populates the Bound-client picker with the realm's OIDC clients (searchable). */
  clientApi?: { list(realmId: string): Promise<Client[]> };
  /** Optional — populates the Roles multi-select with the realm's roles. */
  roleApi?: { list(realmId: string): Promise<Role[]> };
  /** Optional — populates the Roles multi-select with the bound client's client-roles. */
  clientRoleApi?: { listRoles(realmId: string, clientId: string): Promise<ClientRole[]> };
}

interface Note { tone: ToastTone; title: string; message?: string; }

const STATUS_TONE: Record<string, BadgeTone> = {
  ACTIVE: "success", SUSPENDED: "warning", EXPIRED: "danger", REVOKED: "danger",
};

/** Owner-integrity verdict → badge tone: valid = calm, orphaned = danger (zombie), unknown = warning. */
const OWNER_TONE: Record<OwnerStatus, BadgeTone> = {
  VALID: "success", ORPHANED: "danger", UNKNOWN: "warning",
};

function ownerStatusLabel(status: OwnerStatus, t: (key: string) => string): string {
  return t(`agents.ownerStatus.${status.toLowerCase()}`);
}

/** Rows per page in the agent list before paging kicks in. */
const PAGE_SIZE = 8;

function agentLabel(a: Agent, t: (key: string) => string): string {
  return a.displayName?.trim() || a.name?.trim() || t("agents.unnamed");
}

function statusLabel(status: string, t: (key: string) => string): string {
  return t(`agents.status.${(status ?? "").toLowerCase()}`);
}

function fmtDate(ms: number | null): string {
  if (!ms) return "—";
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** The nhi.* identity claims every token this agent mints carries — mirrors the backend AgentTokenEnricher. */
function tokenClaims(a: Agent): Array<[string, string]> {
  const claims: Array<[string, string]> = [["nhi", "true"], ["agent_id", a.id]];
  if (a.name?.trim()) claims.push(["agent_name", a.name.trim()]);
  if (a.owner?.trim()) claims.push(["agent_owner", a.owner.trim()]);
  if (a.description?.trim()) claims.push(["agent_purpose", a.description.trim()]);
  return claims;
}

/**
 * Helix IAM Agent (NHI): a first-class registry for AI agents / non-human identities. Each agent has an
 * accountable human owner and a lifecycle that is the kill-switch — suspend or revoke and the agent stops
 * minting tokens immediately. Tokens it gets carry an `nhi` marker plus its id / owner / purpose.
 */
export function AgentsPage({ api, realmId, boundClientId, embedded, userApi, clientApi, roleApi, clientRoleApi }: AgentsPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<Agent[] | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);
  const [editing, setEditing] = React.useState<Agent | "new" | null>(null);
  const [selected, setSelected] = React.useState<Agent | null>(null);
  const [toDelete, setToDelete] = React.useState<Agent | null>(null);
  const [page, setPage] = React.useState(0);
  const [ownerReviews, setOwnerReviews] = React.useState<AgentOwnerReview[]>([]);
  const [ownerOptions, setOwnerOptions] = React.useState<ComboOption[]>([]);
  const [clientOptions, setClientOptions] = React.useState<ComboOption[]>([]);
  const [realmRoleOptions, setRealmRoleOptions] = React.useState<ComboOption[]>([]);

  // Populate the Owner / Bound-client pickers from the realm (best-effort; the form still allows free text).
  React.useEffect(() => {
    if (!userApi) return;
    userApi.list(realmId)
      .then((users) => setOwnerOptions(users.map((u) => ({ value: u.email ?? u.username, label: u.username, description: u.email ?? undefined }))))
      .catch(() => setOwnerOptions([]));
  }, [userApi, realmId]);
  React.useEffect(() => {
    if (!clientApi) return;
    clientApi.list(realmId)
      .then((clients) => setClientOptions(clients.map((c) => ({ value: c.clientId, label: c.clientId }))))
      .catch(() => setClientOptions([]));
  }, [clientApi, realmId]);
  React.useEffect(() => {
    if (!roleApi) return;
    const groupLabel = t("agents.roles.group.realm");
    roleApi.list(realmId)
      .then((roles) => setRealmRoleOptions(roles.map((r) => ({ value: r.name, label: r.name, group: groupLabel }))))
      .catch(() => setRealmRoleOptions([]));
  }, [roleApi, realmId, t]);

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => { setRows([]); setNote({ tone: "error", title: t("agents.load.error"), message: String(e.message ?? e) }); });
    // Owner-integrity review runs alongside the list; a failure here just hides the governance signals.
    api.ownerReview(realmId).then(setOwnerReviews).catch(() => setOwnerReviews([]));
  }, [api, realmId, t]);
  React.useEffect(reload, [reload]);

  const submit = async (id: string | null, body: AgentWrite) => {
    try {
      if (id) await api.update(realmId, id, body); else await api.create(realmId, body);
      setEditing(null);
      setNote({ tone: "success", title: id ? t("agents.updated") : t("agents.registered") });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("agents.save.error"), message: String((e as Error).message ?? e) });
    }
  };

  const lifecycle = async (a: Agent, action: "suspend" | "activate" | "revoke") => {
    try {
      await api[action](realmId, a.id);
      setNote({ tone: "success", title: action === "activate" ? t("agents.activated") : action === "suspend" ? t("agents.suspended") : t("agents.revoked") });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: action === "activate" ? t("agents.activate.error") : action === "suspend" ? t("agents.suspend.error") : t("agents.revoke.error"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    const a = toDelete; setToDelete(null);
    if (!a) return;
    try { await api.remove(realmId, a.id); setNote({ tone: "success", title: t("agents.deleted") }); reload(); }
    catch (e: unknown) { setNote({ tone: "error", title: t("agents.delete.error"), message: String((e as Error).message ?? e) }); }
  };

  // When embedded in an Application tab, scope the list to that app's client.
  const list = rows && boundClientId ? rows.filter((a) => a.clientId === boundClientId) : rows;

  // Keep the open drawer in sync with the latest list, so a lifecycle change reflects without reopening.
  const selectedLive = selected && list ? (list.find((a) => a.id === selected.id) ?? selected) : selected;
  const stats = list && list.length > 0 ? agentStats(list, Date.now()) : null;
  const paged = paginate(list ?? [], page, PAGE_SIZE);

  // Owner integrity: id→status map + the agents whose owner is not a live realm user (needing review).
  const ownerMap = ownerStatusById(ownerReviews);
  const ownerIssues = ownerIssueCount(ownerReviews);
  const flagged = (list ?? []).filter((a) => (ownerMap[a.id] ?? "VALID") !== "VALID");

  const menuItems = (a: Agent): RowMenuItem[] => {
    const items: RowMenuItem[] = [];
    if (a.status === "ACTIVE") items.push({ label: t("agents.row.suspend"), onSelect: () => lifecycle(a, "suspend") });
    else items.push({ label: t("agents.row.activate"), onSelect: () => lifecycle(a, "activate") });
    if (a.status !== "REVOKED") items.push({ label: t("agents.row.revoke"), onSelect: () => lifecycle(a, "revoke") });
    items.push({ label: t("common.delete"), danger: true, onSelect: () => setToDelete(a) });
    return items;
  };

  return (
    <Page>
      {!embedded && (
        <PageHeader
          title={t("agents.title")}
          description={t("agents.description", { realm: realmId })}
          actions={<Button variant="primary" onClick={() => setEditing("new")}>{t("agents.register")}</Button>}
        />
      )}

      <PageBody>
        {embedded && (
          <PageToolbar>
            <div className="hx-muted hx-toolbar__grow">{t("agents.embedded.description")}</div>
            <Button variant="primary" onClick={() => setEditing("new")}>{t("agents.register")}</Button>
          </PageToolbar>
        )}

        {!embedded && stats && (
          <div className="hx-agentstats">
            <StatCard label={t("agents.stat.total")} value={stats.total} />
            <StatCard label={t("agents.stat.active")} value={stats.active} />
            <StatCard label={t("agents.stat.suspended")} value={stats.suspended} tone={stats.suspended ? "warn" : undefined} />
            <StatCard label={t("agents.stat.revoked")} value={stats.revoked} tone={stats.revoked ? "warn" : undefined} />
            <StatCard label={t("agents.stat.expiringSoon")} value={stats.expiringSoon} tone={stats.expiringSoon ? "warn" : undefined} />
            <StatCard label={t("agents.stat.ownerIssues")} value={ownerIssues} tone={ownerIssues ? "warn" : undefined} />
          </div>
        )}

        {!embedded && flagged.length > 0 && (
          <Section title={t("agents.ownerreview.title")} description={t("agents.ownerreview.desc")}>
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr>
                    <th>{t("agents.table.agent")}</th><th>{t("agents.drawer.field.owner")}</th>
                    <th>{t("agents.ownerreview.col.ownerstatus")}</th>
                    <th className="hx-col-actions" aria-label={t("agents.table.actions")} />
                  </tr>
                </thead>
                <tbody>
                  {flagged.map((a) => (
                    <tr key={a.id}>
                      <td><button type="button" className="hx-textbtn" onClick={() => setSelected(a)}>{agentLabel(a, t)}</button></td>
                      <td className="hx-mono hx-muted">{a.owner?.trim() || <span className="hx-faint">—</span>}</td>
                      <td><Badge tone={OWNER_TONE[ownerMap[a.id] ?? "VALID"]}>{ownerStatusLabel(ownerMap[a.id] ?? "VALID", t)}</Badge></td>
                      <td className="hx-cell-right">
                        <div className="hx-badges">
                          <Button variant="ghost" onClick={() => setEditing(a)}>{t("agents.ownerreview.reassign")}</Button>
                          {a.status === "ACTIVE" && <Button variant="ghost" onClick={() => lifecycle(a, "suspend")}>{t("agents.row.suspend")}</Button>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )}

        {list === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("agents.loading")} />
          </div>
        ) : list.length === 0 ? (
          <EmptyState
            title={t("agents.empty.title")}
            message={t("agents.empty.msg")}
            action={<Button variant="primary" onClick={() => setEditing("new")}>{t("agents.register")}</Button>}
          />
        ) : (
          <>
            {/* desktop table */}
            <div className="hx-card hx-show-desktop">
              <div className="hx-tablescroll">
                <table className="hx-table">
                  <thead>
                    <tr>
                      <th>{t("agents.table.agent")}</th><th>{t("agents.table.owner")}</th><th>{t("agents.table.status")}</th><th>{t("agents.table.auth")}</th>
                      {!boundClientId && <th>{t("agents.table.client")}</th>}
                      <th>{t("agents.table.lastUsed")}</th>
                      <th className="hx-col-actions" aria-label={t("agents.table.actions")} />
                    </tr>
                  </thead>
                  <tbody>
                    {paged.items.map((a) => (
                      <tr key={a.id}>
                        <td>
                          <div className="hx-namecell">
                            <button type="button" className="hx-textbtn" onClick={() => setSelected(a)}>{agentLabel(a, t)}</button>
                          </div>
                          {a.description?.trim() && <div className="hx-help">{a.description}</div>}
                        </td>
                        <td>{a.owner?.trim() || <span className="hx-faint">—</span>}</td>
                        <td><Badge tone={STATUS_TONE[a.status] ?? "neutral"}>{statusLabel(a.status, t)}</Badge></td>
                        <td className="hx-muted">{a.authMethod}</td>
                        {!boundClientId && <td className="hx-mono hx-muted">{a.clientId?.trim() || <span className="hx-faint">—</span>}</td>}
                        <td className="hx-muted">{fmtDate(a.lastUsedAt)}</td>
                        <td className="hx-cell-right">
                          <RowMenu items={menuItems(a)} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* mobile cards */}
            <div className="hx-cards hx-show-mobile">
              {paged.items.map((a) => (
                <div className="hx-rowcard hx-rowcard--link" key={a.id} role="button" tabIndex={0}
                  onClick={() => setSelected(a)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSelected(a); } }}>
                  <div className="hx-rowcard__head">
                    <div className="hx-rowcard__grow">
                      <div className="hx-rowcard__title">{agentLabel(a, t)}</div>
                      {a.description?.trim() && <div className="hx-rowcard__sub">{a.description}</div>}
                    </div>
                    <div className="hx-rowcard__actions" onClick={(e) => e.stopPropagation()}>
                      <Badge tone={STATUS_TONE[a.status] ?? "neutral"}>{statusLabel(a.status, t)}</Badge>
                      <RowMenu items={menuItems(a)} />
                    </div>
                  </div>
                  <div className="hx-rowcard__fields">
                    <div className="hx-rowcard__field">
                      <span className="hx-rowcard__label">{t("agents.card.owner")}</span>
                      <span className="hx-rowcard__value">{a.owner?.trim() || "—"}</span>
                    </div>
                    <div className="hx-rowcard__field">
                      <span className="hx-rowcard__label">{t("agents.card.auth")}</span>
                      <span className="hx-rowcard__value">{a.authMethod}</span>
                    </div>
                    {!boundClientId && (
                      <div className="hx-rowcard__field">
                        <span className="hx-rowcard__label">{t("agents.card.client")}</span>
                        <span className="hx-rowcard__value hx-mono">{a.clientId?.trim() || "—"}</span>
                      </div>
                    )}
                    <div className="hx-rowcard__field">
                      <span className="hx-rowcard__label">{t("agents.card.lastUsed")}</span>
                      <span className="hx-rowcard__value">{fmtDate(a.lastUsedAt)}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {paged.pageCount > 1 && (
              <div className="hx-pager">
                <span className="hx-pager__info">{t("agents.page.info", { page: String(paged.page + 1), pages: String(paged.pageCount) })}</span>
                <div className="hx-pager__nav">
                  <Button variant="ghost" onClick={() => setPage(paged.page - 1)} disabled={paged.page === 0}>{t("agents.page.prev")}</Button>
                  <Button variant="ghost" onClick={() => setPage(paged.page + 1)} disabled={paged.page + 1 >= paged.pageCount}>{t("agents.page.next")}</Button>
                </div>
              </div>
            )}
          </>
        )}
      </PageBody>

      <Modal open={editing !== null} title={editing === "new" ? t("agents.modal.register") : t("agents.modal.edit")} onClose={() => setEditing(null)} width={560}>
        {editing !== null && (
          <AgentForm
            initial={editing === "new" ? null : editing}
            fixedClientId={boundClientId}
            ownerOptions={ownerOptions}
            clientOptions={clientOptions}
            realmRoleOptions={realmRoleOptions}
            realmId={realmId}
            clientRoleApi={clientRoleApi}
            onCancel={() => setEditing(null)}
            onSubmit={(body) => submit(editing === "new" ? null : editing.id, body)}
          />
        )}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("agents.confirm.delete.title")}
        message={t("agents.confirm.delete.msg", { name: toDelete ? agentLabel(toDelete, t) : t("agents.this") })}
        onConfirm={confirmDelete}
        onCancel={() => setToDelete(null)}
      />

      <Drawer
        open={selectedLive !== null}
        onClose={() => setSelected(null)}
        title={selectedLive ? agentLabel(selectedLive, t) : t("agents.drawer.title")}
        footer={selectedLive && (
          <div className="hx-drawer-acts">
            <Button variant="ghost" onClick={() => { const a = selectedLive; setSelected(null); setEditing(a); }}>{t("agents.drawer.edit")}</Button>
            {selectedLive.status === "ACTIVE"
              ? <Button variant="ghost" onClick={() => lifecycle(selectedLive, "suspend")}>{t("agents.row.suspend")}</Button>
              : <Button variant="ghost" onClick={() => lifecycle(selectedLive, "activate")}>{t("agents.row.activate")}</Button>}
            {selectedLive.status !== "REVOKED" && (
              <Button variant="danger" onClick={() => lifecycle(selectedLive, "revoke")}>{t("agents.row.revoke")}</Button>
            )}
          </div>
        )}
      >
        {selectedLive && <AgentDetail agent={selectedLive} ownerStatus={ownerMap[selectedLive.id]} t={t} />}
      </Drawer>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

function AgentForm({ initial, fixedClientId, ownerOptions, clientOptions, realmRoleOptions, realmId, clientRoleApi, onSubmit, onCancel }: { initial: Agent | null; fixedClientId?: string; ownerOptions: ComboOption[]; clientOptions: ComboOption[]; realmRoleOptions: ComboOption[]; realmId: string; clientRoleApi?: { listRoles(realmId: string, clientId: string): Promise<ClientRole[]> }; onSubmit: (b: AgentWrite) => void; onCancel: () => void }) {
  const { t } = useT();
  const [name, setName] = React.useState(initial?.name ?? "");
  const [displayName, setDisplayName] = React.useState(initial?.displayName ?? "");
  const [description, setDescription] = React.useState(initial?.description ?? "");
  const [owner, setOwner] = React.useState(initial?.owner ?? "");
  const [authMethod, setAuthMethod] = React.useState(initial?.authMethod ?? "SECRET");
  const [clientId, setClientId] = React.useState(initial?.clientId ?? fixedClientId ?? "");
  const [scopes, setScopes] = React.useState(initial?.scopes ?? "");
  const [roles, setRoles] = React.useState(initial?.roles ?? "");
  const [clientRoleOptions, setClientRoleOptions] = React.useState<ComboOption[]>([]);
  const [expiresAt, setExpiresAt] = React.useState(initial?.expiresAt ? fmtDate(initial.expiresAt) : "");

  // Load the bound client's client-roles (encoded clientId/roleName) so they can be picked alongside realm roles.
  React.useEffect(() => {
    const c = clientId.trim();
    if (!clientRoleApi || !c) { setClientRoleOptions([]); return; }
    const group = t("agents.roles.group.client", { client: c });
    clientRoleApi.listRoles(realmId, c)
      .then((cr) => setClientRoleOptions(cr.map((r) => ({ value: `${c}/${r.name}`, label: r.name, description: c, group }))))
      .catch(() => setClientRoleOptions([]));
  }, [clientRoleApi, realmId, clientId, t]);
  const roleOptions = React.useMemo(() => [...realmRoleOptions, ...clientRoleOptions], [realmRoleOptions, clientRoleOptions]);
  const [attempted, setAttempted] = React.useState(false);
  const errors = validateAgent({ name, owner });

  const save = () => {
    setAttempted(true);
    if (errors.length) return;
    const expMs = expiresAt.trim() ? Date.parse(expiresAt.trim()) : null;
    onSubmit({
      name: name.trim(), displayName: displayName.trim() || null, description: description.trim() || null,
      owner: owner.trim(), authMethod, clientId: clientId.trim() || null, scopes: scopes.trim() || null,
      roles: roles.trim() || null, expiresAt: Number.isNaN(expMs as number) ? null : expMs,
    });
  };

  return (
    <div>
      <FormField label={t("agents.form.name")} required hint={t("agents.form.name.hint")} error={attempted && errors.includes("name") ? t("agents.form.name.error") : undefined}>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="billing-bot" />
      </FormField>
      <FormField label={t("agents.form.displayName")} hint={t("agents.form.displayName.hint")}>
        <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Billing reconciliation bot" />
      </FormField>
      <FormField label={t("agents.form.purpose")} hint={t("agents.form.purpose.hint")}>
        <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="reconciles invoices nightly" />
      </FormField>
      <FormField label={t("agents.form.owner")} required hint={t("agents.form.owner.hint")} error={attempted && errors.includes("owner") ? t("agents.form.owner.error") : undefined}>
        <Combobox value={owner} onChange={setOwner} options={ownerOptions} allowCustom placeholder="alice@acme.example" aria-label={t("agents.form.owner")} />
      </FormField>
      <FormField label={t("agents.form.auth")} hint={t("agents.form.auth.hint")}>
        <Select
          value={authMethod}
          onChange={setAuthMethod}
          options={[
            { value: "SECRET", label: t("agents.form.auth.secret") },
            { value: "JWT", label: t("agents.form.auth.jwt") },
            { value: "FEDERATED", label: t("agents.form.auth.federated") },
          ]}
        />
      </FormField>
      <FormField label={t("agents.form.client")} hint={fixedClientId ? t("agents.form.client.hint.fixed") : t("agents.form.client.hint")}>
        {fixedClientId
          ? <Input value={clientId} disabled placeholder="billing-bot-client" />
          : <Combobox value={clientId} onChange={setClientId} options={clientOptions} allowCustom placeholder="billing-bot-client" aria-label={t("agents.form.client")} />}
      </FormField>
      <FormField label={t("agents.form.scopes")} hint={t("agents.form.scopes.hint")}>
        <Input value={scopes} onChange={(e) => setScopes(e.target.value)} placeholder="openid invoices:read" />
      </FormField>
      <FormField label={t("agents.form.roles")} hint={t("agents.form.roles.hint")}>
        <MultiCombobox
          values={parseCsv(roles)}
          onChange={(vals) => setRoles(vals.join(" "))}
          options={roleOptions}
          placeholder={t("agents.form.roles.placeholder")}
          emptyText={t("agents.form.roles.empty")}
          aria-label={t("agents.form.roles")}
        />
      </FormField>
      <FormField label={t("agents.form.expires")} hint={t("agents.form.expires.hint")}>
        <Input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
      </FormField>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{initial ? t("agents.form.save") : t("agents.register")}</Button>
      </div>
    </div>
  );
}

/** One governance overview tile — a big count over a label. `warn` colours the number when it needs attention. */
function StatCard({ label, value, tone }: { label: string; value: number; tone?: "warn" }) {
  return (
    <Card>
      <div className="hx-stat">
        <div className={tone === "warn" ? "hx-stat__value hx-stat__value--warn" : "hx-stat__value"}>{value}</div>
        <div className="hx-stat__label">{label}</div>
      </div>
    </Card>
  );
}

type Translate = (key: string, vars?: Record<string, string | number>) => string;

/**
 * The agent identity detail panel — the demo Keycloak can't reproduce: an accountable owner, the least-
 * privilege capabilities (attenuation), and the exact nhi.* markers every token this agent mints carries,
 * with a prominent kill-switch in the drawer footer.
 */
function AgentDetail({ agent, ownerStatus, t }: { agent: Agent; ownerStatus?: OwnerStatus; t: Translate }) {
  const scopes = parseCsv(agent.scopes);
  const roles = parseCsv(agent.roles);
  const claims = tokenClaims(agent);
  return (
    <>
      <div className="hx-drawer-group">
        <div className="hx-badges">
          <Badge tone="accent">{t("agents.nhi.badge")}</Badge>
          <Badge tone={STATUS_TONE[agent.status] ?? "neutral"}>{statusLabel(agent.status, t)}</Badge>
          {agent.expiresAt ? <Badge tone="neutral">{t("agents.expiring.badge", { date: fmtDate(agent.expiresAt) })}</Badge> : null}
        </div>
      </div>

      <div className="hx-drawer-group">
        <h4 className="hx-drawer-group__head">{t("agents.drawer.section.identity")}</h4>
        <DetailList>
          <Detail label={t("agents.drawer.field.owner")}>
            <span className="hx-badges">
              {agent.owner?.trim() || "—"}
              {ownerStatus && <Badge tone={OWNER_TONE[ownerStatus]}>{ownerStatusLabel(ownerStatus, t)}</Badge>}
            </span>
          </Detail>
          {agent.description?.trim() ? <Detail label={t("agents.drawer.field.purpose")}>{agent.description}</Detail> : null}
          <Detail label={t("agents.drawer.field.auth")}>{agent.authMethod}</Detail>
          <Detail label={t("agents.drawer.field.client")} mono={agent.clientId?.trim() || undefined}>
            {agent.clientId?.trim() ? undefined : "—"}
          </Detail>
          <Detail label={t("agents.drawer.field.registered")}>{fmtDate(agent.createdAt)}</Detail>
          <Detail label={t("agents.drawer.field.lastUsed")}>{fmtDate(agent.lastUsedAt)}</Detail>
          {agent.expiresAt ? <Detail label={t("agents.drawer.field.expires")}>{fmtDate(agent.expiresAt)}</Detail> : null}
          <Detail label={t("agents.drawer.field.id")} mono={agent.id} />
        </DetailList>
      </div>

      <div className="hx-drawer-group">
        <h4 className="hx-drawer-group__head">{t("agents.drawer.section.attenuation")}</h4>
        <p className="hx-drawer-group__desc">{t("agents.drawer.attenuation.desc")}</p>
        <DetailList>
          <Detail label={t("agents.drawer.scopes")}>
            {scopes.length
              ? <span className="hx-badges">{scopes.map((s) => <Badge key={s} tone="accent">{s}</Badge>)}</span>
              : <span className="hx-faint">{t("agents.drawer.none")}</span>}
          </Detail>
          <Detail label={t("agents.drawer.roles")}>
            {roles.length
              ? <span className="hx-badges">{roles.map((r) => <Badge key={r} tone="neutral">{r}</Badge>)}</span>
              : <span className="hx-faint">{t("agents.drawer.none")}</span>}
          </Detail>
        </DetailList>
      </div>

      <div className="hx-drawer-group">
        <h4 className="hx-drawer-group__head">{t("agents.drawer.section.token")}</h4>
        <p className="hx-drawer-group__desc">{t("agents.drawer.token.desc")}</p>
        <div>
          {claims.map(([k, v]) => (
            <div className="hx-claimrow" key={k}>
              <span className="hx-claimrow__key">{k}</span>
              <span className="hx-claimrow__val">{v}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="hx-drawer-group">
        <h4 className="hx-drawer-group__head">{t("agents.drawer.section.killswitch")}</h4>
        <p className="hx-drawer-group__desc">{t("agents.drawer.killswitch.desc")}</p>
      </div>
    </>
  );
}
