/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Modal } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { FormField, Input } from "../components/FormField";
import { ApplicationApi, Application, ApplicationWrite, applicationId, applicationLabel, validateApplication } from "../api/applications";
import { ClientApi } from "../api/clients";
import { SamlClientApi } from "../api/samlClients";
import { useT } from "../i18n/LocaleContext";

export interface ApplicationsPageProps {
  api: ApplicationApi;
  clientApi: ClientApi;
  samlClientApi: SamlClientApi;
  realmId: string;
  onOpen: (name: string) => void;
}

interface Note { tone: ToastTone; title: string; message?: string; }
interface Row { app: Application; oidc: boolean; saml: boolean; }

/**
 * The unified Applications list (WSO2/Okta model): one screen for every app, each showing which
 * protocols (OIDC / SAML) hang below it. Replaces the separate Clients + SAML-clients screens.
 */
export function ApplicationsPage({ api, clientApi, samlClientApi, realmId, onOpen }: ApplicationsPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<Row[] | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    setRows(null);
    Promise.all([api.list(realmId), clientApi.list(realmId), samlClientApi.list(realmId)])
      .then(([apps, clients, sps]) => {
        const oidcIds = new Set(clients.map((c) => c.applicationId).filter(Boolean));
        const samlIds = new Set(sps.map((s) => s.applicationId).filter(Boolean));
        setRows(
          apps
            .map((app) => {
              const id = applicationId(realmId, app.name);
              return { app, oidc: oidcIds.has(id), saml: samlIds.has(id) };
            })
            .sort((a, b) => applicationLabel(a.app).localeCompare(applicationLabel(b.app))),
        );
      })
      .catch((e) => {
        setRows([]);
        setNote({ tone: "error", title: t("applications.loadError"), message: String(e.message ?? e) });
      });
  }, [api, clientApi, samlClientApi, realmId, t]);
  React.useEffect(reload, [reload]);

  const create = async (write: ApplicationWrite) => {
    setBusy(true);
    try {
      const created = await api.create(realmId, write);
      setCreating(false);
      setNote({ tone: "success", title: t("applications.createSuccess"), message: t("applications.createSuccessMessage", { name: applicationLabel(created) }) });
      reload();
      onOpen(created.name);
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("applications.createError"), message: String((e as Error).message ?? e) });
    } finally { setBusy(false); }
  };

  return (
    <Page>
      <PageHeader
        title={t("applications.title")}
        description={<>{t("applications.descriptionPrefix")} <strong>{realmId}</strong>{t("applications.descriptionSuffix")}</>}
        actions={<Button variant="primary" onClick={() => setCreating(true)}>{t("applications.create")}</Button>}
      />

      <PageBody>
      {rows === null ? (
        <div className="hx-loadwrap">
          <Spinner size={28} label={t("applications.loading")} />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title={t("applications.emptyTitle")} message={t("applications.emptyMessage")}
          action={<Button variant="primary" onClick={() => setCreating(true)}>{t("applications.create")}</Button>} />
      ) : (
        <>
          {/* desktop table */}
          <div className="hx-card hx-show-desktop">
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr><th>{t("applications.colApp")}</th><th>{t("applications.colProtocols")}</th><th>{t("applications.colSubjectClaim")}</th><th>{t("applications.colLoginFlow")}</th><th>{t("applications.colStatus")}</th></tr>
                </thead>
                <tbody>
                  {rows.map(({ app, oidc, saml }) => (
                    <tr key={app.name} onClick={() => onOpen(app.name)} className="hx-row-clickable">
                      <td>
                        <strong>{applicationLabel(app)}</strong>
                        {app.displayName && app.displayName.trim()
                          ? <div className="hx-conn__alias">{app.name}</div>
                          : null}
                        {app.description ? <div className="hx-help">{app.description}</div> : null}
                      </td>
                      <td>
                        <span className="hx-badges">
                          {oidc ? <Badge tone="accent">OIDC</Badge> : null}
                          {saml ? <Badge tone="accent">SAML</Badge> : null}
                          {!oidc && !saml ? <span className="hx-faint">{t("applications.noneYet")}</span> : null}
                        </span>
                      </td>
                      <td className="hx-mono">{app.subjectClaim ?? <span className="hx-faint">{t("applications.realmDefault")}</span>}</td>
                      <td className="hx-mono">{app.authFlowAlias ?? <span className="hx-faint">{t("applications.browserDefault")}</span>}</td>
                      <td><Badge tone={app.enabled ? "accent" : "neutral"}>{app.enabled ? t("applications.enabled") : t("applications.disabled")}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* mobile cards */}
          <div className="hx-cards hx-show-mobile">
            {rows.map(({ app, oidc, saml }) => (
              <div className="hx-rowcard hx-rowcard--clickable" key={app.name} onClick={() => onOpen(app.name)}>
                <div className="hx-rowcard__head">
                  <div className="hx-rowcard__grow">
                    <div className="hx-rowcard__title">{applicationLabel(app)}</div>
                    {app.displayName && app.displayName.trim()
                      ? <div className="hx-rowcard__sub hx-mono">{app.name}</div>
                      : null}
                    {app.description ? <div className="hx-rowcard__sub">{app.description}</div> : null}
                  </div>
                  <Badge tone={app.enabled ? "accent" : "neutral"}>{app.enabled ? t("applications.enabled") : t("applications.disabled")}</Badge>
                </div>
                <div className="hx-rowcard__fields">
                  <div className="hx-rowcard__field">
                    <span className="hx-rowcard__label">{t("applications.colProtocols")}</span>
                    <span className="hx-rowcard__value">
                      {oidc ? <Badge tone="accent">OIDC</Badge> : null}
                      {saml ? <Badge tone="accent">SAML</Badge> : null}
                      {!oidc && !saml ? <span className="hx-faint">{t("applications.noneYet")}</span> : null}
                    </span>
                  </div>
                  <div className="hx-rowcard__field">
                    <span className="hx-rowcard__label">{t("applications.colSubjectClaim")}</span>
                    <span className="hx-rowcard__value hx-mono">
                      {app.subjectClaim ?? <span className="hx-faint">{t("applications.realmDefault")}</span>}
                    </span>
                  </div>
                  <div className="hx-rowcard__field">
                    <span className="hx-rowcard__label">{t("applications.colLoginFlow")}</span>
                    <span className="hx-rowcard__value hx-mono">
                      {app.authFlowAlias ?? <span className="hx-faint">{t("applications.browserDefault")}</span>}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      </PageBody>

      <Modal open={creating} title={t("applications.modalTitle")} onClose={() => setCreating(false)} width={520}>
        {busy ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("applications.creating")} /></div>
        ) : (
          <CreateApplicationForm onSubmit={create} onCancel={() => setCreating(false)} />
        )}
      </Modal>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

/** Turn a friendly display name into a stable, URL-safe identifier (lower-kebab). */
function slugify(s: string): string {
  return s.trim().toLowerCase().replace(/[^\w.@:-]+/g, "-").replace(/^-+|-+$/g, "").replace(/-{2,}/g, "-");
}

function CreateApplicationForm({ onSubmit, onCancel }: { onSubmit: (w: ApplicationWrite) => void; onCancel: () => void }) {
  const { t } = useT();
  const [displayName, setDisplayName] = React.useState("");
  const [name, setName] = React.useState("");
  const [idEdited, setIdEdited] = React.useState(false);
  const [description, setDescription] = React.useState("");
  const [attempted, setAttempted] = React.useState(false);
  const errors = validateApplication({ name });

  // Auto-derive the identifier from the display name until the admin edits it by hand.
  const onDisplayName = (v: string) => {
    setDisplayName(v);
    if (!idEdited) setName(slugify(v));
  };

  const submit = () => {
    setAttempted(true);
    if (!displayName.trim() || Object.keys(errors).length) return;
    onSubmit({ name: name.trim(), displayName: displayName.trim(), description: description.trim() || null, enabled: true });
  };

  return (
    <div>
      <FormField label={t("applications.form.displayName")} required error={attempted && !displayName.trim() ? t("applications.form.displayNameRequired") : undefined}
        hint={t("applications.form.displayNameHint")}>
        <Input value={displayName} onChange={(e) => onDisplayName(e.target.value)} placeholder={t("applications.form.displayNamePlaceholder")} autoFocus />
      </FormField>
      <FormField label={t("applications.form.identifier")} required error={attempted ? errors.name : undefined}
        hint={t("applications.form.identifierHint")}>
        <Input value={name} onChange={(e) => { setIdEdited(true); setName(e.target.value); }} placeholder="gov-portal" />
      </FormField>
      <FormField label={t("applications.form.description")} hint={t("applications.form.descriptionHint")}>
        <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("applications.form.descriptionPlaceholder")} />
      </FormField>
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={submit}>{t("applications.create")}</Button>
      </div>
    </div>
  );
}
