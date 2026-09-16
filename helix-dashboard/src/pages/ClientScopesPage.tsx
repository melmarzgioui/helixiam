/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Badge } from "../components/Badge";
import { FormField, Input } from "../components/FormField";
import { RowMenu } from "../components/RowMenu";
import { ScopeApi, ClientScope } from "../api/scopes";
import { useT } from "../i18n/LocaleContext";

export interface ClientScopesPageProps {
  api: ScopeApi;
  realmId: string;
  /** Open the scope detail page (where claims are added). */
  onOpen: (scopeId: string) => void;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/** E8.5: Client scopes — a table of scopes; click a row to open the scope and manage its claims. */
export function ClientScopesPage({ api, realmId, onOpen }: ClientScopesPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<ClientScope[] | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [toDelete, setToDelete] = React.useState<ClientScope | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => { setRows([]); setNote({ tone: "error", title: t("clientScopes.loadError"), message: String(e.message ?? e) }); });
  }, [api, realmId, t]);
  React.useEffect(reload, [reload]);

  const submit = async (body: { name: string; description?: string }) => {
    try {
      const s = await api.create(realmId, body);
      setCreating(false);
      reload();
      onOpen(s.scopeId);
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("clientScopes.createError"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const t2 = toDelete; setToDelete(null);
    try {
      await api.remove(realmId, t2.scopeId);
      setNote({ tone: "info", title: t("clientScopes.deleteSuccess"), message: t("clientScopes.deleteSuccessMsg", { name: t2.name }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("clientScopes.deleteError"), message: String((e as Error).message ?? e) });
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("clientScopes.title")}
        description={<>{t("clientScopes.descriptionPrefix")} <strong>{realmId}</strong> {t("clientScopes.descriptionSuffix")}</>}
        actions={<Button variant="primary" onClick={() => setCreating(true)}>{t("clientScopes.create")}</Button>}
      />

      <PageBody>
      {rows === null ? (
        <div className="hx-loadwrap"><Spinner size={28} label={t("clientScopes.loading")} /></div>
      ) : rows.length === 0 ? (
        <EmptyState title={t("clientScopes.emptyTitle")} message={t("clientScopes.emptyMessage")} action={<Button variant="primary" onClick={() => setCreating(true)}>{t("clientScopes.create")}</Button>} />
      ) : (
        <>
          {/* desktop table */}
          <div className="hx-card hx-show-desktop">
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr><th>{t("clientScopes.colScope")}</th><th>{t("clientScopes.colClaims")}</th><th className="hx-cell-right">{t("clientScopes.colTotal")}</th><th className="hx-col-actions" aria-label="Actions" /></tr>
                </thead>
                <tbody>
                  {rows.map((s) => (
                    <tr key={s.scopeId} onClick={() => onOpen(s.scopeId)} className="hx-row-clickable">
                      <td>
                        <div className="hx-rowcard__title">{s.name}</div>
                        {s.description && <div className="hx-rowcard__sub">{s.description}</div>}
                      </td>
                      <td>
                        <span className="hx-badges">
                          {s.claimPreview.length ? s.claimPreview.map((c) => <Badge key={c} tone="neutral">{c}</Badge>) : <span className="hx-faint">{t("clientScopes.noClaims")}</span>}
                          {s.claimCount > s.claimPreview.length && <Badge tone="accent">{t("clientScopes.moreClaims", { count: s.claimCount - s.claimPreview.length })}</Badge>}
                        </span>
                      </td>
                      <td className="hx-cell-right hx-muted">{s.claimCount}</td>
                      <td className="hx-cell-right" onClick={(e) => e.stopPropagation()}>
                        <RowMenu items={[
                          { label: t("clientScopes.openScope"), onSelect: () => onOpen(s.scopeId) },
                          { label: t("clientScopes.deleteScope"), danger: true, onSelect: () => setToDelete(s) },
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
            {rows.map((s) => (
              <div className="hx-rowcard hx-rowcard--clickable" key={s.scopeId} onClick={() => onOpen(s.scopeId)}>
                <div className="hx-rowcard__head">
                  <div className="hx-rowcard__grow">
                    <div className="hx-rowcard__title">{s.name}</div>
                    {s.description && <div className="hx-rowcard__sub">{s.description}</div>}
                  </div>
                  <Badge tone="neutral">{t("clientScopes.claimsCount", { count: s.claimCount })}</Badge>
                </div>
                <div className="hx-rowcard__fields">
                  <div className="hx-rowcard__field">
                    <span className="hx-rowcard__label">{t("clientScopes.colClaims")}</span>
                    <span className="hx-rowcard__value">
                      {s.claimPreview.length ? s.claimPreview.map((c) => <Badge key={c} tone="neutral">{c}</Badge>) : <span className="hx-faint">{t("clientScopes.noClaims")}</span>}
                      {s.claimCount > s.claimPreview.length && <Badge tone="accent">{t("clientScopes.moreClaims", { count: s.claimCount - s.claimPreview.length })}</Badge>}
                    </span>
                  </div>
                </div>
                <div className="hx-rowcard__actions" onClick={(e) => e.stopPropagation()}>
                  <Button variant="ghost" onClick={() => onOpen(s.scopeId)}>{t("clientScopes.open")}</Button>
                  <Button variant="ghost" onClick={() => setToDelete(s)}>{t("common.delete")}</Button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      </PageBody>

      <Modal open={creating} title={t("clientScopes.modalTitle")} onClose={() => setCreating(false)} width={480}>
        <ScopeForm onSubmit={submit} onCancel={() => setCreating(false)} />
      </Modal>
      <ConfirmDialog
        open={toDelete !== null}
        title={t("clientScopes.deleteTitle")}
        message={t("clientScopes.deleteMessage", { name: toDelete?.name ?? "" })}
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

function ScopeForm({ onSubmit, onCancel }: { onSubmit: (b: { name: string; description?: string }) => void; onCancel: () => void }) {
  const { t } = useT();
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [attempted, setAttempted] = React.useState(false);
  const missing = !name.trim();
  const save = () => { if (missing) { setAttempted(true); return; } onSubmit({ name: name.trim(), description: description.trim() || undefined }); };
  return (
    <div>
      <FormField label={t("clientScopes.form.name")} required error={attempted && missing ? t("clientScopes.form.nameRequired") : undefined}>
        <Input value={name} autoFocus placeholder="profile" onChange={(e) => setName(e.target.value)} />
      </FormField>
      <FormField label={t("clientScopes.form.description")} hint={t("clientScopes.form.descriptionHint")}>
        <Input value={description} placeholder={t("clientScopes.form.descriptionPlaceholder")} onChange={(e) => setDescription(e.target.value)} />
      </FormField>
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{t("clientScopes.create")}</Button>
      </div>
    </div>
  );
}
