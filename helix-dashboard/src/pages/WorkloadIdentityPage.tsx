import React from "react";
import { Page, PageHeader, PageBody, PageToolbar } from "../components/Page";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Alert } from "../components/Alert";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { FormField, Input } from "../components/FormField";
import { Switch } from "../components/Switch";
import { RowMenu } from "../components/RowMenu";
import {
  WorkloadIdentityApi,
  WorkloadIdentityCredential,
  WorkloadIdentityWrite,
  validateWorkloadIdentity,
} from "../api/workloadIdentity";
import { useT } from "../i18n/LocaleContext";

export interface WorkloadIdentityPageProps {
  api: WorkloadIdentityApi;
  realmId: string;
  /**
   * When set, the page is scoped to one Application's OIDC client (its service account): the list is
   * filtered to that client and new credentials are fixed to act as it (no free-text "acts as").
   */
  boundClientId?: string;
  /** Whether the bound client has its service account (client_credentials grant) enabled. */
  serviceAccountEnabled?: boolean;
  /** Read-only cross-application overview (the top-level page): show the table, no add/edit/delete. */
  readOnly?: boolean;
  /** Render without the full page header (when embedded in the Application detail tab). */
  embedded?: boolean;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/**
 * Helix IAM WIF: per-realm Workload Identity Federation credentials. A credential lets a workload (a
 * Kubernetes pod's projected ServiceAccount token, a CI OIDC token) exchange its issuer-signed JWT for a
 * Helix token with NO client secret — keyless. Each credential binds an exact issuer + subject + audience
 * to an Application's OIDC client (its service account); the minted token carries that client's roles +
 * scopes. Configured on the Application's "Workload identity" tab; the standalone page is a read-only
 * cross-application overview.
 */
export function WorkloadIdentityPage({ api, realmId, boundClientId, serviceAccountEnabled, readOnly, embedded }: WorkloadIdentityPageProps) {
  const { t } = useT();
  const [all, setAll] = React.useState<WorkloadIdentityCredential[] | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);
  const [editing, setEditing] = React.useState<WorkloadIdentityCredential | "new" | null>(null);
  const [toDelete, setToDelete] = React.useState<WorkloadIdentityCredential | null>(null);

  const reload = React.useCallback(() => {
    setAll(null);
    api.list(realmId).then(setAll).catch((e) => {
      setAll([]);
      setNote({ tone: "error", title: t("workloadIdentity.errLoad"), message: String(e.message ?? e) });
    });
  }, [api, realmId]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(reload, [reload]);

  const rows = all === null ? null : boundClientId ? all.filter((c) => c.clientId === boundClientId) : all;

  const submit = async (id: string | null, body: WorkloadIdentityWrite) => {
    try {
      if (id) await api.update(realmId, id, body); else await api.create(realmId, body);
      setEditing(null);
      setNote({ tone: "success", title: id ? t("workloadIdentity.toastUpdated") : t("workloadIdentity.toastCreated") });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("workloadIdentity.errSave"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    const c = toDelete; setToDelete(null);
    if (!c) return;
    try { await api.remove(realmId, c.id); setNote({ tone: "success", title: t("workloadIdentity.toastDeleted") }); reload(); }
    catch (e: unknown) { setNote({ tone: "error", title: t("workloadIdentity.errDelete"), message: String((e as Error).message ?? e) }); }
  };

  const canAdd = !readOnly && (!boundClientId || serviceAccountEnabled);

  return (
    <Page>
      {!embedded && (
        <PageHeader
          title={t("workloadIdentity.title")}
          description={readOnly
            ? <>{t("workloadIdentity.descReadOnlyPre")} <strong>{realmId}</strong>{t("workloadIdentity.descReadOnlyMid")} <strong>{t("workloadIdentity.title")}</strong> {t("workloadIdentity.descReadOnlyPost")}</>
            : <>{t("workloadIdentity.descPre")} <strong>{realmId}</strong> {t("workloadIdentity.descMid")} <strong>{t("workloadIdentity.descNoSecret")}</strong>.</>}
          actions={canAdd ? <Button variant="primary" onClick={() => setEditing("new")}>{t("workloadIdentity.addCredential")}</Button> : undefined}
        />
      )}

      <PageBody>
        {embedded && (
          <PageToolbar>
            <div className="hx-muted hx-toolbar__grow">
              {t("workloadIdentity.toolbarPre")} <strong>{t("workloadIdentity.toolbarStrong")}</strong>{t("workloadIdentity.toolbarPost")}
            </div>
            {canAdd && <Button variant="primary" onClick={() => setEditing("new")}>{t("workloadIdentity.addCredential")}</Button>}
          </PageToolbar>
        )}

        {embedded && boundClientId && !serviceAccountEnabled && (
          <Alert tone="warning">
            {t("workloadIdentity.alertSaPre")} <strong>{t("workloadIdentity.alertSaStrong")}</strong> ({t("workloadIdentity.alertSaGrantPrefix")} <code>client_credentials</code> {t("workloadIdentity.alertSaGrantSuffix")}
          </Alert>
        )}

        {rows === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("workloadIdentity.loadingCredentials")} />
          </div>
        ) : rows.length === 0 ? (
          embedded
            ? (serviceAccountEnabled
                ? <p className="hx-faint">{t("workloadIdentity.emptyEmbedded")}</p>
                : null)
            : (
              <EmptyState
                title={t("workloadIdentity.emptyTitle")}
                message={<>{t("workloadIdentity.emptyMsgBase")} {readOnly ? t("workloadIdentity.emptyMsgReadOnly") : t("workloadIdentity.emptyMsgEdit")}</>}
                action={readOnly ? undefined : <Button variant="primary" onClick={() => setEditing("new")}>{t("workloadIdentity.addFirst")}</Button>}
              />
            )
        ) : (
          <>
            {/* desktop table */}
            <div className="hx-card hx-show-desktop">
              <div className="hx-tablescroll">
                <table className="hx-table">
                  <thead>
                    <tr>
                      <th>{t("workloadIdentity.colName")}</th>
                      <th>{t("workloadIdentity.colIssuer")}</th>
                      <th>{t("workloadIdentity.colSubject")}</th>
                      <th>{t("workloadIdentity.colAudience")}</th>
                      {!boundClientId && <th>{t("workloadIdentity.colActsAs")}</th>}
                      <th>{t("workloadIdentity.colStatus")}</th>
                      {!readOnly && <th className="hx-col-actions" aria-label={t("workloadIdentity.actionsLabel")} />}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((c) => (
                      <tr key={c.id}>
                        <td>
                          <div className="hx-namecell">
                            {readOnly
                              ? (c.name?.trim() || <span className="hx-faint">—</span>)
                              : <button type="button" className="hx-textbtn" onClick={() => setEditing(c)}>{c.name?.trim() || "—"}</button>}
                          </div>
                        </td>
                        <td className="hx-mono hx-muted">{c.issuer}</td>
                        <td className="hx-mono hx-muted">{c.subject}</td>
                        <td className="hx-muted">{c.audience}</td>
                        {!boundClientId && <td className="hx-mono hx-muted">{c.clientId}</td>}
                        <td><Badge tone={c.enabled ? "success" : "neutral"}>{c.enabled ? t("workloadIdentity.statusEnabled") : t("workloadIdentity.statusDisabled")}</Badge></td>
                        {!readOnly && (
                          <td className="hx-cell-right">
                            <RowMenu items={[{ label: t("common.delete"), danger: true, onSelect: () => setToDelete(c) }]} />
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* mobile cards */}
            <div className="hx-cards hx-show-mobile">
              {rows.map((c) => (
                <div className="hx-rowcard" key={c.id}>
                  <div className="hx-rowcard__head">
                    <div className="hx-rowcard__grow">
                      <div className="hx-rowcard__title">
                        {readOnly
                          ? (c.name?.trim() || "—")
                          : <button type="button" className="hx-textbtn" onClick={() => setEditing(c)}>{c.name?.trim() || "—"}</button>}
                      </div>
                      <div className="hx-rowcard__sub hx-mono">{c.issuer}</div>
                    </div>
                    <div className="hx-rowcard__actions">
                      <Badge tone={c.enabled ? "success" : "neutral"}>{c.enabled ? t("workloadIdentity.statusEnabled") : t("workloadIdentity.statusDisabled")}</Badge>
                      {!readOnly && <RowMenu items={[{ label: t("common.delete"), danger: true, onSelect: () => setToDelete(c) }]} />}
                    </div>
                  </div>
                  <div className="hx-rowcard__fields">
                    <div className="hx-rowcard__field">
                      <span className="hx-rowcard__label">{t("workloadIdentity.colSubject")}</span>
                      <span className="hx-rowcard__value hx-mono">{c.subject}</span>
                    </div>
                    <div className="hx-rowcard__field">
                      <span className="hx-rowcard__label">{t("workloadIdentity.colAudience")}</span>
                      <span className="hx-rowcard__value">{c.audience}</span>
                    </div>
                    {!boundClientId && (
                      <div className="hx-rowcard__field">
                        <span className="hx-rowcard__label">{t("workloadIdentity.colActsAs")}</span>
                        <span className="hx-rowcard__value hx-mono">{c.clientId}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </PageBody>

      <Modal open={editing !== null} title={editing === "new" ? t("workloadIdentity.modalAddTitle") : t("workloadIdentity.modalEditTitle")} onClose={() => setEditing(null)} width={580}>
        {editing !== null && (
          <CredentialForm
            initial={editing === "new" ? null : editing}
            fixedClientId={boundClientId}
            onCancel={() => setEditing(null)}
            onSubmit={(body) => submit(editing === "new" ? null : editing.id, body)}
          />
        )}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("workloadIdentity.confirmDeleteTitle")}
        message={t("workloadIdentity.confirmDeleteMsg", { subject: toDelete?.subject ?? "" })}
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

function CredentialForm({
  initial, fixedClientId, onSubmit, onCancel,
}: { initial: WorkloadIdentityCredential | null; fixedClientId?: string; onSubmit: (b: WorkloadIdentityWrite) => void; onCancel: () => void }) {
  const { t } = useT();
  const [name, setName] = React.useState(initial?.name ?? "");
  const [issuer, setIssuer] = React.useState(initial?.issuer ?? "");
  const [jwksUri, setJwksUri] = React.useState(initial?.jwksUri ?? "");
  const [subject, setSubject] = React.useState(initial?.subject ?? "");
  const [audience, setAudience] = React.useState(initial?.audience ?? "helix");
  const [clientId, setClientId] = React.useState(initial?.clientId ?? fixedClientId ?? "");
  const [scopes, setScopes] = React.useState(initial?.scopes ?? "");
  const [enabled, setEnabled] = React.useState(initial?.enabled ?? true);
  const [attempted, setAttempted] = React.useState(false);

  const effectiveClientId = fixedClientId ?? clientId;
  const body: WorkloadIdentityWrite = {
    name: name.trim(), issuer: issuer.trim(), jwksUri: jwksUri.trim() || null,
    subject: subject.trim(), audience: audience.trim(), clientId: effectiveClientId.trim(),
    scopes: scopes.trim() || null, enabled,
  };
  const errors = validateWorkloadIdentity(body);
  const err = (k: string) => attempted && errors.includes(k);

  const save = () => {
    setAttempted(true);
    if (errors.length) return;
    onSubmit(body);
  };

  return (
    <div>
      {fixedClientId && (
        <p className="hx-help">
          {t("workloadIdentity.formActsAsPre")} <strong>{fixedClientId}</strong> {t("workloadIdentity.formActsAsPost")}
        </p>
      )}
      <FormField label={t("workloadIdentity.fieldName")} required error={err("name") ? t("workloadIdentity.errNameRequired") : undefined} hint={t("workloadIdentity.fieldNameHint")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Prod cluster (apps/billing)" />
      </FormField>
      <FormField label={t("workloadIdentity.fieldIssuer")} required error={err("issuer") ? t("workloadIdentity.errInvalidUrl") : undefined}
        hint={t("workloadIdentity.fieldIssuerHint")}>
        <Input value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="https://kubernetes.default.svc.cluster.local" />
      </FormField>
      <FormField label={t("workloadIdentity.fieldJwksUrl")} error={err("jwksUri") ? t("workloadIdentity.errInvalidUrl") : undefined}
        hint={t("workloadIdentity.fieldJwksUrlHint")}>
        <Input value={jwksUri} onChange={(e) => setJwksUri(e.target.value)} placeholder="https://…/openid/v1/jwks" />
      </FormField>
      <FormField label={t("workloadIdentity.fieldSubject")} required error={err("subject") ? t("workloadIdentity.errSubjectRequired") : undefined}
        hint={t("workloadIdentity.fieldSubjectHint")}>
        <Input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="system:serviceaccount:apps:billing" />
      </FormField>
      <FormField label={t("workloadIdentity.fieldAudience")} required error={err("audience") ? t("workloadIdentity.errAudienceRequired") : undefined}
        hint={t("workloadIdentity.fieldAudienceHint")}>
        <Input value={audience} onChange={(e) => setAudience(e.target.value)} placeholder="helix" />
      </FormField>
      {!fixedClientId && (
        <FormField label={t("workloadIdentity.fieldActsAs")} required error={err("clientId") ? t("workloadIdentity.errClientRequired") : undefined}
          hint={t("workloadIdentity.fieldActsAsHint")}>
          <Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="billing-service" />
        </FormField>
      )}
      <FormField label={t("workloadIdentity.fieldScopes")} hint={t("workloadIdentity.fieldScopesHint")}>
        <Input value={scopes} onChange={(e) => setScopes(e.target.value)} placeholder="billing.read billing.write" />
      </FormField>
      <FormField label={t("workloadIdentity.fieldStatus")}>
        <Switch checked={enabled} onChange={setEnabled} label={t("workloadIdentity.fieldEnabled")} />
      </FormField>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{initial ? t("workloadIdentity.saveChanges") : t("workloadIdentity.addCredential")}</Button>
      </div>
    </div>
  );
}
