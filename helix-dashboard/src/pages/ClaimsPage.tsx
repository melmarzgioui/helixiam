/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Badge } from "../components/Badge";
import { Switch } from "../components/Switch";
import { FormField, Input } from "../components/FormField";
import { Select } from "../components/Select";
import { RowMenu } from "../components/RowMenu";
import { ClaimApi, Claim, ClaimWrite } from "../api/scopes";
import { useT } from "../i18n/LocaleContext";

export interface ClaimsPageProps {
  api: ClaimApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/** E8.5: the claim catalogue (preset) — the master list of claim types a realm supports. Scopes map from here. */
export function ClaimsPage({ api, realmId }: ClaimsPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<Claim[] | null>(null);
  const [editing, setEditing] = React.useState<Claim | null | "new">(null);
  const [toDelete, setToDelete] = React.useState<Claim | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);
  const [subject, setSubject] = React.useState<string>("");
  const [loadedSubject, setLoadedSubject] = React.useState<string>("");
  const [savingSubject, setSavingSubject] = React.useState(false);

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => { setRows([]); setNote({ tone: "error", title: t("claims.loadError"), message: String(e.message ?? e) }); });
  }, [api, realmId, t]);
  React.useEffect(reload, [reload]);
  React.useEffect(() => {
    api.getSubject(realmId).then((s) => { setSubject(s.claimKey); setLoadedSubject(s.claimKey); }).catch(() => undefined);
  }, [api, realmId]);

  const saveSubject = async () => {
    setSavingSubject(true);
    try {
      const s = await api.setSubject(realmId, subject);
      setLoadedSubject(s.claimKey);
      const fromText = subject === "sub" ? t("claims.internalSubjectId") : `"${subject}"`;
      setNote({ tone: "success", title: t("claims.subjectUpdated"), message: t("claims.subjectUpdatedMsg", { from: fromText }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("claims.saveSubjectError"), message: String((e as Error).message ?? e) });
    } finally {
      setSavingSubject(false);
    }
  };

  const submit = async (body: ClaimWrite) => {
    try {
      if (editing && editing !== "new") {
        await api.update(realmId, editing.claimId, body);
        setNote({ tone: "success", title: t("claims.updateSuccess"), message: t("claims.updateSuccessMsg", { label: body.label }) });
      } else {
        await api.create(realmId, body);
        setNote({ tone: "success", title: t("claims.addSuccess"), message: t("claims.addSuccessMsg", { label: body.label }) });
      }
      setEditing(null);
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("claims.saveError"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const td = toDelete; setToDelete(null);
    try {
      await api.remove(realmId, td.claimId);
      setNote({ tone: "info", title: t("claims.removeSuccess"), message: t("claims.removeSuccessMsg", { label: td.label }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("claims.removeError"), message: String((e as Error).message ?? e) });
    }
  };

  const menuItems = (c: Claim) => [
    { label: t("claims.editClaim"), onSelect: () => setEditing(c) },
    { label: t("claims.deleteClaim"), danger: true, onSelect: () => setToDelete(c) },
  ];

  const claimBadge = (c: Claim) => (c.mandatory ? <Badge tone="accent">{t("claims.mandatory")}</Badge> : <Badge tone="neutral">{t("claims.optional")}</Badge>);

  return (
    <Page>
      <PageHeader
        title={t("claims.title")}
        description={<>{t("claims.descriptionPrefix")} <strong>{realmId}</strong> {t("claims.descriptionSuffix")}</>}
        actions={<Button variant="primary" onClick={() => setEditing("new")}>{t("claims.addClaim")}</Button>}
      />

      <PageBody>
      {rows && rows.length > 0 && (
        <Section title={t("claims.subjectTitle")} description={<>{t("claims.subjectDescPre")} <code className="hx-mono">sub</code> {t("claims.subjectDescPost")}</>}>
          <div className="hx-secret__row">
            <Select
              aria-label={t("claims.subjectTitle")}
              value={subject}
              onChange={setSubject}
              options={[
                { value: "sub", label: t("claims.subjectDefault") },
                ...rows.filter((c) => c.key !== "sub").map((c) => ({ value: c.key, label: `${c.label} (${c.key})` })),
              ]}
            />
            <Button variant="primary" disabled={savingSubject || subject === loadedSubject} onClick={saveSubject}>
              {savingSubject ? t("claims.savingSubject") : t("common.save")}
            </Button>
          </div>
        </Section>
      )}

      {rows === null ? (
        <div className="hx-loadwrap"><Spinner size={28} label={t("claims.loading")} /></div>
      ) : rows.length === 0 ? (
        <EmptyState title={t("claims.emptyTitle")} message={t("claims.emptyMessage")} action={<Button variant="primary" onClick={() => setEditing("new")}>{t("claims.addClaim")}</Button>} />
      ) : (
        <>
          {/* desktop table */}
          <div className="hx-card hx-show-desktop">
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr><th>{t("claims.colClaim")}</th><th>{t("claims.colKey")}</th><th>{t("claims.colExample")}</th><th>{t("claims.colRequired")}</th><th className="hx-col-actions" aria-label="Actions" /></tr>
                </thead>
                <tbody>
                  {rows.map((c) => (
                    <tr key={c.claimId}>
                      <td><strong>{c.label}</strong></td>
                      <td><span className="hx-conn__alias">{c.key}</span></td>
                      <td>{c.placeholder ? <span className="hx-muted">{c.placeholder}</span> : <span className="hx-faint">—</span>}</td>
                      <td>{claimBadge(c)}</td>
                      <td className="hx-cell-right">
                        <RowMenu items={menuItems(c)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* mobile cards */}
          <div className="hx-cards hx-show-mobile">
            {rows.map((c) => (
              <div className="hx-rowcard" key={c.claimId}>
                <div className="hx-rowcard__head">
                  <div className="hx-rowcard__grow">
                    <div className="hx-rowcard__title hx-namecell">
                      {c.label}{claimBadge(c)}
                    </div>
                    <div className="hx-rowcard__sub hx-mono">{c.key}</div>
                  </div>
                  <div className="hx-rowcard__actions">
                    <RowMenu items={menuItems(c)} />
                  </div>
                </div>
                <div className="hx-rowcard__fields">
                  <div className="hx-rowcard__field">
                    <span className="hx-rowcard__label">{t("claims.exampleLabel")}</span>
                    <span className="hx-rowcard__value">{c.placeholder ?? <span className="hx-faint">—</span>}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      </PageBody>

      <Modal open={editing !== null} title={editing && editing !== "new" ? t("claims.editModalTitle") : t("claims.addModalTitle")} onClose={() => setEditing(null)} width={480}>
        {editing !== null && (
          <ClaimForm key={editing === "new" ? "new" : editing.claimId} initial={editing === "new" ? null : editing} onSubmit={submit} onCancel={() => setEditing(null)} />
        )}
      </Modal>
      <ConfirmDialog
        open={toDelete !== null}
        title={t("claims.deleteTitle")}
        message={t("claims.deleteMessage", { label: toDelete?.label ?? "" })}
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

function ClaimForm({ initial, onSubmit, onCancel }: { initial: Claim | null; onSubmit: (b: ClaimWrite) => void; onCancel: () => void }) {
  const { t } = useT();
  const editing = !!initial;
  const [label, setLabel] = React.useState(initial?.label ?? "");
  const [key, setKey] = React.useState(initial?.key ?? "");
  const [placeholder, setPlaceholder] = React.useState(initial?.placeholder ?? "");
  const [mandatory, setMandatory] = React.useState(initial?.mandatory ?? false);
  const [attempted, setAttempted] = React.useState(false);
  const missing: string[] = [];
  if (!label.trim()) missing.push("label");
  if (!key.trim()) missing.push("key");
  const save = () => { if (missing.length) { setAttempted(true); return; } onSubmit({ key: key.trim(), label: label.trim(), placeholder: placeholder.trim() || undefined, mandatory }); };
  const err = (k: string) => (attempted && missing.includes(k) ? t("claims.form.fieldRequired") : undefined);
  return (
    <div>
      <FormField label={t("claims.form.displayName")} required error={err("label")}>
        <Input value={label} autoFocus placeholder="Nationality" onChange={(e) => setLabel(e.target.value)} />
      </FormField>
      <FormField label={t("claims.form.claimKey")} required error={err("key")} hint={editing ? t("claims.form.immutableHint") : t("claims.form.claimKeyHint")}>
        <Input value={key} placeholder="nationality" disabled={editing} readOnly={editing} onChange={(e) => setKey(e.target.value.replace(/\s+/g, "_").toLowerCase())} />
      </FormField>
      <FormField label={t("claims.form.exampleValue")} hint={t("claims.form.exampleHint")}>
        <Input value={placeholder} placeholder="NL" onChange={(e) => setPlaceholder(e.target.value)} />
      </FormField>
      <div className="hx-togglelist">
        <div className="hx-togglerow">
          <div className="hx-colstack">
            <label htmlFor="claim-mandatory" className="hx-togglerow__label">{t("claims.form.mandatory")}</label>
            <span className="hx-help">{t("claims.form.mandatoryHelp")}</span>
          </div>
          <Switch id="claim-mandatory" checked={mandatory} onChange={setMandatory} />
        </div>
      </div>
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{editing ? t("claims.form.saveChanges") : t("claims.addClaim")}</Button>
      </div>
    </div>
  );
}
