/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, PageToolbar } from "../components/Page";
import { Button } from "../components/Button";
import { RowMenu } from "../components/RowMenu";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { FormField, Input, Textarea } from "../components/FormField";
import { Select } from "../components/Select";
import { Switch } from "../components/Switch";
import { SUPPORTED_CLAIMS, claimLabel, claimDef } from "../components/claimCatalog";
import { UserApi, UserSummary, UserWrite } from "../api/users";
import { RoleApi, Role } from "../api/roles";
import { useT } from "../i18n/LocaleContext";

export interface UsersPageProps {
  api: UserApi;
  roleApi: RoleApi;
  realmId: string;
  /** Open a user's detail page (Details · Role mappings · Device & passkeys · Sessions). */
  onOpen?: (userId: string) => void;
}

export interface Note { tone: ToastTone; title: string; message?: string; }

/** E8.5-S1: the live Users screen — realm-scoped user management backed by the admin API. */
export function UsersPage({ api, roleApi, realmId, onOpen }: UsersPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<UserSummary[] | null>(null);
  const [query, setQuery] = React.useState("");
  const [editorOpen, setEditorOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<UserSummary | null>(null);
  const [resetting, setResetting] = React.useState<UserSummary | null>(null);
  const [managing, setManaging] = React.useState<UserSummary | null>(null);
  const [toDelete, setToDelete] = React.useState<UserSummary | null>(null);
  const [importOpen, setImportOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);

  const submitImport = async (payload: string) => {
    setBusy(true);
    try {
      const result = await api.importUsers(realmId, payload);
      const parts = [
        t("users.import.result.created", { count: result.created }),
        t("users.import.result.skipped", { count: result.skipped }),
      ];
      if (result.failed.length) parts.push(t("users.import.result.failed", { count: result.failed.length }));
      setNote({
        tone: result.failed.length ? "info" : "success",
        title: t("users.import.done"),
        message: parts.join(" · ") + (result.failed.length ? t("users.import.result.firstError", { username: result.failed[0].username || "—", error: result.failed[0].error }) : ""),
      });
      setImportOpen(false);
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.import.failed"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => {
      setRows([]);
      setNote({ tone: "error", title: t("users.load.error"), message: String(e.message ?? e) });
    });
  }, [api, realmId, t]);

  React.useEffect(reload, [reload]);

  const filtered = (rows ?? []).filter((u) => {
    const q = query.trim().toLowerCase();
    return !q || u.username.toLowerCase().includes(q) || (u.email ?? "").toLowerCase().includes(q);
  });

  const openCreate = () => { setEditing(null); setEditorOpen(true); };
  const openEdit = (u: UserSummary) => { setEditing(u); setEditorOpen(true); };
  const closeEditor = () => { setEditorOpen(false); setEditing(null); };

  const submit = async (write: UserWrite) => {
    setBusy(true);
    try {
      if (editing) {
        await api.update(realmId, editing.userId, write);
        setNote({ tone: "success", title: t("users.updated"), message: t("users.updated.msg", { name: write.username }) });
      } else {
        await api.create(realmId, write);
        setNote({ tone: "success", title: t("users.created"), message: t("users.created.msg", { name: write.username, realm: realmId }) });
      }
      closeEditor();
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.save.error"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const toggleEnabled = async (u: UserSummary) => {
    try {
      await api.update(realmId, u.userId, { username: u.username, email: u.email ?? undefined, enabled: !u.enabled, locked: u.locked, attributes: u.attributes });
      setNote({ tone: "info", title: u.enabled ? t("users.disabled") : t("users.enabled"), message: u.username });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.update.error"), message: String((e as Error).message ?? e) });
    }
  };

  const submitReset = async (newPassword: string) => {
    if (!resetting) return;
    const target = resetting;
    setResetting(null);
    try {
      await api.resetPassword(realmId, target.userId, newPassword);
      setNote({ tone: "success", title: t("users.password.reset"), message: t("users.password.reset.msg", { name: target.username }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.password.reset.error"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const target = toDelete;
    setToDelete(null);
    try {
      await api.remove(realmId, target.userId);
      setNote({ tone: "info", title: t("users.removed"), message: t("users.removed.msg", { name: target.username, realm: realmId }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.remove.error"), message: String((e as Error).message ?? e) });
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("users.title")}
        description={t("users.description", { realm: realmId })}
        actions={<>
          <Button variant="ghost" onClick={() => setImportOpen(true)}>{t("users.import")}</Button>
          <Button variant="primary" onClick={openCreate}>{t("users.add")}</Button>
        </>}
      />

      <PageBody>
        {rows === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("users.loading")} />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title={t("users.empty.title")}
            message={t("users.empty.msg")}
            action={<Button variant="primary" onClick={openCreate}>{t("users.add")}</Button>}
          />
        ) : (
          <>
            <PageToolbar>
              <div className="hx-toolbar__grow">
                <Input placeholder={t("users.search.placeholder")} value={query} onChange={(e) => setQuery(e.target.value)} aria-label={t("users.search.aria")} />
              </div>
            </PageToolbar>

            {/* desktop table */}
            <div className="hx-card hx-show-desktop">
              <div className="hx-tablescroll">
                <table className="hx-table">
                  <thead>
                    <tr>
                      <th>{t("users.table.user")}</th><th>{t("users.table.roles")}</th><th>{t("users.table.mfa")}</th><th>{t("users.table.status")}</th>
                      <th className="hx-col-actions" aria-label={t("users.table.actions")} />
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((u) => (
                      <tr key={u.userId}>
                        <td>
                          <div className="hx-conn">
                            <Avatar name={u.username} />
                            <div>
                              <button type="button" className="hx-textbtn" onClick={() => onOpen?.(u.userId)}>{u.username}</button>
                              <div className="hx-conn__alias">{u.email ?? u.userId.slice(0, 8)}</div>
                            </div>
                          </div>
                        </td>
                        <td>{u.roles.length ? u.roles.map((r) => <Badge key={r} tone="neutral">{r}</Badge>) : <span className="hx-faint">—</span>}</td>
                        <td>{u.mfaEnabled ? <Badge tone="success">{t("users.table.mfa")}</Badge> : <span className="hx-faint">Off</span>}</td>
                        <td><StatusBadge enabled={u.enabled} locked={u.locked} /></td>
                        <td className="hx-cell-right">
                          <RowMenu items={[
                            ...(onOpen ? [{ label: t("users.row.open"), onSelect: () => onOpen(u.userId) }] : []),
                            { label: t("users.row.edit"), onSelect: () => openEdit(u) },
                            { label: t("users.row.manageRoles"), onSelect: () => setManaging(u) },
                            { label: u.enabled ? t("users.row.disable") : t("users.row.enable"), onSelect: () => toggleEnabled(u) },
                            { label: t("users.row.resetPassword"), onSelect: () => setResetting(u) },
                            { label: t("users.row.remove"), danger: true, onSelect: () => setToDelete(u) },
                          ]} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* mobile cards */}
            <div className="hx-cards hx-show-mobile">
              {filtered.map((u) => (
                <div className={onOpen ? "hx-conncard hx-row-clickable" : "hx-conncard"} key={u.userId} onClick={() => onOpen?.(u.userId)}>
                  <Avatar name={u.username} size={38} />
                  <div className="hx-conncard__body">
                    <div className="hx-conn__name">{u.username}</div>
                    <div className="hx-conncard__row">
                      <StatusBadge enabled={u.enabled} locked={u.locked} />
                      {u.mfaEnabled && <Badge tone="success">{t("users.mfa.on")}</Badge>}
                    </div>
                  </div>
                  <div className="hx-rowcard__actions">
                    <Button variant="ghost" onClick={() => openEdit(u)}>{t("common.edit")}</Button>
                    <Button variant="ghost" onClick={() => setToDelete(u)}>{t("common.delete")}</Button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </PageBody>

      <Modal open={editorOpen} title={editing ? t("users.modal.edit") : t("users.modal.add")} onClose={closeEditor} width={560}>
        {busy ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("users.saving")} /></div>
        ) : (
          <UserForm key={editing?.userId ?? "new"} initial={editing} onSubmit={submit} onCancel={closeEditor} />
        )}
      </Modal>

      <Modal open={resetting !== null} title={t("users.modal.resetPassword")} onClose={() => setResetting(null)} width={460}>
        <ResetForm username={resetting?.username ?? ""} onSubmit={submitReset} onCancel={() => setResetting(null)} />
      </Modal>

      <Modal open={managing !== null} title={t("users.modal.roles", { name: managing?.username ?? "" })} onClose={() => { setManaging(null); reload(); }} width={460}>
        {managing && <RolesManager roleApi={roleApi} realmId={realmId} user={managing} onNote={setNote} />}
      </Modal>

      <Modal open={importOpen} title={t("users.import.title")} onClose={() => setImportOpen(false)} width={620}>
        <ImportUsersForm busy={busy} onSubmit={submitImport} onCancel={() => setImportOpen(false)} />
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("users.confirm.remove.title")}
        message={t("users.confirm.remove.msg", { name: toDelete?.username ?? "", realm: realmId })}
        onConfirm={confirmDelete}
        onCancel={() => setToDelete(null)}
      />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

export function Avatar({ name, size = 34 }: { name: string; size?: number }) {
  const initials = name.replace(/@.*/, "").slice(0, 2).toUpperCase();
  return (
    <span
      aria-hidden="true"
      className="hx-avatar hx-avatar--sized"
      style={{ ["--avatar-size" as never]: `${size}px` }}
    >{initials}</span>
  );
}

export function StatusBadge({ enabled, locked }: { enabled: boolean; locked: boolean }) {
  const { t } = useT();
  if (locked) return <Badge tone="danger">{t("users.status.locked")}</Badge>;
  return <Badge tone={enabled ? "success" : "neutral"}>{enabled ? t("users.status.enabled") : t("users.status.disabled")}</Badge>;
}

/** Create/edit form with required-field validation (blocks submit + shows inline errors). */
export function UserForm({ initial, onSubmit, onCancel }: { initial: UserSummary | null; onSubmit: (w: UserWrite) => void; onCancel: () => void; }) {
  const { t } = useT();
  const editing = !!initial;
  const [username, setUsername] = React.useState(initial?.username ?? "");
  const [email, setEmail] = React.useState(initial?.email ?? "");
  const [password, setPassword] = React.useState("");
  const [enabled, setEnabled] = React.useState(initial?.enabled ?? true);
  // Claims are chosen from the supported set (fixed keys) — never free-form — so the same concept is
  // never stored twice under different keys. New claim types are added at claim-management level.
  const [claims, setClaims] = React.useState<{ k: string; v: string }[]>(
    Object.entries(initial?.attributes ?? {}).map(([k, v]) => ({ k, v }))
  );
  const [attempted, setAttempted] = React.useState(false);

  const used = new Set(claims.map((c) => c.k));
  const available = SUPPORTED_CLAIMS.filter((c) => !used.has(c.key));

  const missing: string[] = [];
  if (!username.trim()) missing.push("username");
  if (!editing && !password.trim()) missing.push("password");

  const addClaim = (key: string) => setClaims((c) => [...c, { k: key, v: "" }]);
  const setClaimValue = (i: number, v: string) => setClaims((c) => c.map((x, j) => j === i ? { ...x, v } : x));
  const removeClaim = (i: number) => setClaims((c) => c.filter((_, j) => j !== i));

  const save = () => {
    if (missing.length) { setAttempted(true); return; }
    const attributes: Record<string, string> = {};
    claims.forEach(({ k, v }) => { if (k && v.trim()) attributes[k] = v; });
    onSubmit({ username: username.trim(), email: email.trim(), password: editing ? undefined : password, enabled, attributes });
  };

  const err = (key: string) => (attempted && missing.includes(key) ? t("users.form.required") : undefined);

  return (
    <div>
      <FormField label={t("users.form.username")} required error={err("username")} hint={t("users.form.username.hint")}>
        <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="j.jansen" disabled={editing} readOnly={editing} />
      </FormField>

      <FormField label={t("users.form.email")} hint={t("users.form.email.hint")}>
        <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="person@organisation.nl" />
      </FormField>

      {!editing && (
        <FormField label={t("users.form.password")} required error={err("password")} hint={t("users.form.password.hint")}>
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </FormField>
      )}

      <div className="hx-mb-4">
        <Switch checked={enabled} onChange={setEnabled} label={t("users.form.accountEnabled")} />
      </div>

      <div className="hx-field">
        <span className="hx-field__label">{t("users.form.claims")}</span>
        <span className="hx-field__hint">{t("users.form.claims.hint")}</span>
      </div>

      {claims.map((c, i) => (
        <FormField key={c.k} label={claimLabel(c.k)}>
          <div className="hx-inputrow">
            <Input value={c.v} onChange={(e) => setClaimValue(i, e.target.value)} aria-label={`${claimLabel(c.k)} value`} placeholder={claimDef(c.k)?.placeholder} />
            <button type="button" className="hx-ghosticon hx-ghosticon--36" aria-label={`Remove ${claimLabel(c.k)}`} onClick={() => removeClaim(i)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
            </button>
          </div>
        </FormField>
      ))}
      {available.length > 0 && (
        <Select
          value=""
          onChange={(v) => v && addClaim(v)}
          placeholder={t("users.form.addClaim")}
          aria-label={t("users.form.addClaim.aria")}
          options={available.map((c) => ({ value: c.key, label: c.label, description: c.group }))}
        />
      )}

      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{editing ? t("users.form.save") : t("users.form.create")}</Button>
      </div>
    </div>
  );
}

export function ResetForm({ username, onSubmit, onCancel }: { username: string; onSubmit: (pw: string) => void; onCancel: () => void; }) {
  const { t } = useT();
  const [pw, setPw] = React.useState("");
  const [attempted, setAttempted] = React.useState(false);
  const save = () => { if (!pw.trim()) { setAttempted(true); return; } onSubmit(pw); };
  return (
    <div>
      <p className="hx-modal__lede">{t("users.reset.intro", { name: username })}</p>
      <FormField label={t("users.reset.newPassword")} required error={attempted && !pw.trim() ? t("users.form.required") : undefined}>
        <Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} />
      </FormField>
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{t("users.reset.submit")}</Button>
      </div>
    </div>
  );
}

/**
 * B10: bulk-import users by pasting a CSV (header row + one user per line) or a JSON array. Users with a
 * blank password are created and asked to set one at first login (UPDATE_PASSWORD). Existing usernames skip.
 */
export function ImportUsersForm({ busy, onSubmit, onCancel }: {
  busy: boolean; onSubmit: (payload: string) => void; onCancel: () => void;
}) {
  const { t } = useT();
  const [text, setText] = React.useState("");
  const sample = "username,email,enabled,firstName,lastName\nada,ada@example.com,true,Ada,Lovelace\ngrace,grace@example.com,true,Grace,Hopper";
  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setText(String(reader.result ?? ""));
    reader.readAsText(file);
  };
  return (
    <div>
      <p className="hx-modal__lede">{t("users.import.intro")}</p>
      <label className="hx-btn hx-btn--ghost hx-mb-4">
        {t("users.import.chooseFile")}
        <input type="file" accept=".csv,.json,text/csv,application/json" onChange={onFile} className="hx-visually-hidden" />
      </label>
      <div className="hx-field">
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={sample}
          spellCheck={false}
          rows={9}
          className="hx-mono"
        />
      </div>
      <div className="hx-formactions">
        <button type="button" className="hx-textbtn" onClick={() => setText(sample)}>{t("users.import.sample")}</button>
        <div className="hx-rowcard__actions">
          <Button variant="ghost" onClick={onCancel} disabled={busy}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={() => onSubmit(text)} disabled={busy || !text.trim()}>{busy ? t("users.import.busy") : t("users.import.submit")}</Button>
        </div>
      </div>
    </div>
  );
}

/** Assign / unassign realm roles to a user — toggles call the API live. */
export function RolesManager({ roleApi, realmId, user, onNote }: {
  roleApi: RoleApi; realmId: string; user: UserSummary; onNote: (n: Note) => void;
}) {
  const { t } = useT();
  const [all, setAll] = React.useState<Role[] | null>(null);
  const [assigned, setAssigned] = React.useState<Set<string>>(new Set());
  const [pending, setPending] = React.useState<string | null>(null);

  React.useEffect(() => {
    Promise.all([roleApi.list(realmId), roleApi.userRoles(realmId, user.userId)])
      .then(([roles, mine]) => { setAll(roles); setAssigned(new Set(mine.map((r) => r.roleId))); })
      .catch((e) => onNote({ tone: "error", title: t("users.roles.load.error"), message: String(e.message ?? e) }));
  }, [roleApi, realmId, user.userId, onNote, t]);

  const toggle = async (role: Role, on: boolean) => {
    setPending(role.roleId);
    try {
      if (on) { await roleApi.assign(realmId, user.userId, role.roleId); setAssigned((s) => new Set(s).add(role.roleId)); }
      else { await roleApi.unassign(realmId, user.userId, role.roleId); setAssigned((s) => { const n = new Set(s); n.delete(role.roleId); return n; }); }
    } catch (e: unknown) {
      onNote({ tone: "error", title: t("users.roles.update.error"), message: String((e as Error).message ?? e) });
    } finally { setPending(null); }
  };

  if (all === null) return <div className="hx-loadwrap"><Spinner size={24} label={t("users.roles.loading")} /></div>;
  if (all.length === 0) return <p className="hx-muted">{t("users.roles.noRoles")}</p>;

  return (
    <div>
      <p className="hx-modal__lede">{t("users.roles.intro", { name: user.username, realm: realmId })}</p>
      <div className="hx-togglelist">
        {all.map((r) => (
          <div className="hx-togglerow" key={r.roleId}>
            <span className="hx-togglerow__label">{r.name}</span>
            <Switch checked={assigned.has(r.roleId)} onChange={(on) => toggle(r, on)} ariaLabel={r.name} disabled={pending === r.roleId} />
          </div>
        ))}
      </div>
    </div>
  );
}
