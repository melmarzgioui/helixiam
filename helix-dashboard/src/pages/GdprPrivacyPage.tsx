/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { FormField, Input, Select } from "../components/FormField";
import { ConfirmDialog } from "../components/Modal";
import { GdprApi, GdprConsentRecord, GdprEraseMode, GdprExport } from "../api/gdpr";
import { UserApi, UserSummary } from "../api/users";
import { useT } from "../i18n/LocaleContext";

export interface GdprPrivacyPageProps {
  api: GdprApi;
  userApi: UserApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/**
 * Helix IAM GDPR / Privacy (admin): exercise data-subject rights for any user in the realm — export their
 * full data (Art. 15/20), view their consent ledger (Art. 7), and erase or anonymize them (Art. 17). Pick a
 * user, then act. Erasure asks for an explicit confirmation and a mode (anonymize keeps an audit tombstone;
 * hard-delete removes everything).
 */
export function GdprPrivacyPage({ api, userApi, realmId }: GdprPrivacyPageProps) {
  const { t } = useT();
  const [users, setUsers] = React.useState<UserSummary[] | null>(null);
  const [selected, setSelected] = React.useState<string>("");
  const [query, setQuery] = React.useState("");
  const [exportData, setExportData] = React.useState<GdprExport | null>(null);
  const [consents, setConsents] = React.useState<GdprConsentRecord[] | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);
  const [eraseMode, setEraseMode] = React.useState<GdprEraseMode>("anonymize");
  const [confirmErase, setConfirmErase] = React.useState(false);

  React.useEffect(() => {
    setUsers(null);
    setSelected("");
    setExportData(null);
    setConsents(null);
    userApi.list(realmId)
      .then(setUsers)
      .catch((e) => { setUsers([]); setNote({ tone: "error", title: t("gdpr.toast.loadUsersError"), message: String(e.message ?? e) }); });
  }, [userApi, realmId]);

  const selectedUser = (users ?? []).find((u) => u.userId === selected) ?? null;

  const loadConsents = React.useCallback((userId: string) => {
    setConsents(null);
    api.consents(realmId, userId)
      .then(setConsents)
      .catch((e) => { setConsents([]); setNote({ tone: "error", title: t("gdpr.toast.loadConsentsError"), message: String(e.message ?? e) }); });
  }, [api, realmId]);

  const onPick = (userId: string) => {
    setSelected(userId);
    setExportData(null);
    if (userId) loadConsents(userId);
    else setConsents(null);
  };

  const runExport = () => {
    if (!selected) return;
    setBusy(true);
    api.export(realmId, selected)
      .then((data) => { setExportData(data); setNote({ tone: "success", title: t("gdpr.toast.exportAssembled") }); })
      .catch((e) => setNote({ tone: "error", title: t("gdpr.toast.exportError"), message: String(e.message ?? e) }))
      .finally(() => setBusy(false));
  };

  const download = () => {
    if (!exportData) return;
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `gdpr-export-${realmId}-${exportData.userId}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const runErase = () => {
    if (!selected) return;
    setBusy(true);
    api.erase(realmId, selected, eraseMode)
      .then((result) => {
        setNote({ tone: "success", title: eraseMode === "hard" ? t("gdpr.toast.erased") : t("gdpr.toast.anonymized"), message: result.userId });
        // Refresh the user list (a hard-deleted user disappears; an anonymized one is renamed + disabled).
        userApi.list(realmId).then(setUsers).catch(() => undefined);
        setSelected("");
        setExportData(null);
        setConsents(null);
      })
      .catch((e) => setNote({ tone: "error", title: t("gdpr.toast.eraseError"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setConfirmErase(false); });
  };

  const filtered = (users ?? []).filter((u) => {
    const q = query.trim().toLowerCase();
    return !q || u.username.toLowerCase().includes(q) || (u.email ?? "").toLowerCase().includes(q);
  });

  return (
    <Page>
      <PageHeader
        title={t("gdpr.title")}
        description={t("gdpr.description", { realmId })}
      />

      <PageBody layout="grid">
        <Section title={t("gdpr.section.subject.title")} description={t("gdpr.section.subject.description")}>
          {users === null ? (
            <Spinner size={20} label={t("gdpr.loading.users")} />
          ) : (
            <>
              <FormField label={t("gdpr.label.findUser")}>
                <Input
                  placeholder={t("gdpr.placeholder.filter")}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </FormField>
              <FormField label={t("gdpr.label.subject")}>
                <Select
                  value={selected}
                  onChange={onPick}
                  placeholder={t("gdpr.placeholder.selectUser")}
                  options={[
                    { value: "", label: t("gdpr.placeholder.selectUser") },
                    ...filtered.map((u) => ({ value: u.userId, label: `${u.username}${u.email ? ` (${u.email})` : ""}` })),
                  ]}
                />
              </FormField>
              {selectedUser && (
                <div className="hx-badges">
                  {selectedUser.enabled ? <Badge tone="accent">enabled</Badge> : <Badge tone="neutral">disabled</Badge>}
                  {selectedUser.locked && <Badge tone="danger">locked</Badge>}
                  {selectedUser.mfaEnabled && <Badge tone="neutral">MFA</Badge>}
                </div>
              )}
            </>
          )}
        </Section>

        <Section
          title={t("gdpr.section.export.title")}
          description={t("gdpr.section.export.description")}
        >
          <div className="hx-toolbar">
            <Button variant="primary" onClick={runExport} disabled={!selected || busy}>
              {busy && !exportData ? t("gdpr.action.assembling") : t("gdpr.action.assembleExport")}
            </Button>
            {exportData && <Button variant="ghost" onClick={download}>{t("gdpr.action.downloadJson")}</Button>}
          </div>
          {exportData && (
            <pre className="hx-codeblock">
              {JSON.stringify(exportData, null, 2)}
            </pre>
          )}
        </Section>

        <Section title={t("gdpr.section.consents.title")} description={t("gdpr.section.consents.description")}>
          {!selected ? (
            <p className="hx-help">{t("gdpr.consents.empty.select")}</p>
          ) : consents === null ? (
            <Spinner size={20} label={t("gdpr.loading.consents")} />
          ) : consents.length === 0 ? (
            <p className="hx-muted">{t("gdpr.consents.empty.none")}</p>
          ) : (
            <div className="hx-cards">
              {consents.map((c) => (
                <Card key={c.id}>
                  <div className="hx-namecell">
                    <strong>{c.clientId}</strong>
                    <Badge tone={c.withdrawnAt === null ? "accent" : "neutral"}>
                      {c.withdrawnAt === null ? t("gdpr.consent.active") : t("gdpr.consent.withdrawn")}
                    </Badge>
                  </div>
                  <div className="hx-help">
                    {c.grantedAt ? t("gdpr.consent.grantedAt", { date: new Date(c.grantedAt).toLocaleString() }) : t("gdpr.consent.granted")}
                    {c.withdrawnAt ? ` · ${t("gdpr.consent.withdrawnAt", { date: new Date(c.withdrawnAt).toLocaleString() })}` : ""}
                  </div>
                  {c.scopes.length > 0 && (
                    <div className="hx-badges">
                      {c.scopes.map((s) => <Badge key={s} tone="neutral">{s}</Badge>)}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          )}
        </Section>

        <Section
          title={t("gdpr.section.erase.title")}
          description={t("gdpr.section.erase.description")}
        >
          <FormField label={t("gdpr.label.mode")}>
            <Select
              value={eraseMode}
              onChange={(v) => setEraseMode(v as GdprEraseMode)}
              options={[
                { value: "anonymize", label: t("gdpr.erase.anonymize") },
                { value: "hard", label: t("gdpr.erase.hard") },
              ]}
            />
          </FormField>
          <Button variant="danger" onClick={() => setConfirmErase(true)} disabled={!selected || busy}>
            {eraseMode === "hard" ? t("gdpr.action.eraseUser") : t("gdpr.action.anonymizeUser")}
          </Button>
        </Section>
      </PageBody>

      <ConfirmDialog
        open={confirmErase}
        title={eraseMode === "hard" ? t("gdpr.confirm.hardDelete.title") : t("gdpr.confirm.anonymize.title")}
        message={
          selectedUser
            ? eraseMode === "hard"
              ? t("gdpr.confirm.hardDelete.message", { username: selectedUser.username })
              : t("gdpr.confirm.anonymize.message", { username: selectedUser.username })
            : ""
        }
        confirmLabel={busy ? t("gdpr.action.working") : eraseMode === "hard" ? t("gdpr.action.hardDelete") : t("gdpr.action.anonymize")}
        onConfirm={runErase}
        onCancel={() => setConfirmErase(false)}
      />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}
