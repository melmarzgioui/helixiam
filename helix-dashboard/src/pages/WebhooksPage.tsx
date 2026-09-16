import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { FormField, Input } from "../components/FormField";
import { Switch } from "../components/Switch";
import { RowMenu } from "../components/RowMenu";
import { Webhook, WebhookApi, WebhookWrite, validateWebhook } from "../api/webhooks";
import { useT } from "../i18n/LocaleContext";

export interface WebhooksPageProps {
  api: WebhookApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/**
 * Helix IAM B6: per-realm outbound webhooks (event-listener SPI). Each matching audit event is POSTed to
 * the endpoint with an HMAC-SHA256 signature (X-Helix-Signature) derived from the shared secret. The
 * event-types filter is a comma-separated allow-list of event types/categories — blank means all events.
 */
export function WebhooksPage({ api, realmId }: WebhooksPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<Webhook[] | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);
  const [editing, setEditing] = React.useState<Webhook | "new" | null>(null);
  const [toDelete, setToDelete] = React.useState<Webhook | null>(null);

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => { setRows([]); setNote({ tone: "error", title: t("webhooks.error.load"), message: String(e.message ?? e) }); });
  }, [api, realmId, t]);
  React.useEffect(reload, [reload]);

  const submit = async (id: string | null, body: WebhookWrite) => {
    try {
      if (id) await api.update(realmId, id, body); else await api.create(realmId, body);
      setEditing(null);
      setNote({ tone: "success", title: id ? t("webhooks.toast.updated") : t("webhooks.toast.created") });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("webhooks.error.save"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    const w = toDelete; setToDelete(null);
    if (!w) return;
    try { await api.remove(realmId, w.id); setNote({ tone: "success", title: t("webhooks.toast.deleted") }); reload(); }
    catch (e: unknown) { setNote({ tone: "error", title: t("webhooks.error.delete"), message: String((e as Error).message ?? e) }); }
  };

  const menuItems = (w: Webhook) => [
    { label: t("webhooks.menu.edit"), onSelect: () => setEditing(w) },
    { label: t("webhooks.menu.delete"), danger: true, onSelect: () => setToDelete(w) },
  ];

  const secretBadge = (w: Webhook) => (w.secretSet ? <Badge tone="neutral">{t("webhooks.badge.signed")}</Badge> : <Badge tone="warning">{t("webhooks.badge.unsigned")}</Badge>);
  const statusBadge = (w: Webhook) => <Badge tone={w.enabled ? "success" : "neutral"}>{w.enabled ? t("webhooks.badge.enabled") : t("webhooks.badge.disabled")}</Badge>;

  return (
    <Page>
      <PageHeader
        title={t("webhooks.title")}
        description={<>{t("webhooks.desc.pre")} <strong>{realmId}</strong>{t("webhooks.desc.mid")}<code>X-Helix-Signature</code> {t("webhooks.desc.end")}</>}
        actions={<Button variant="primary" onClick={() => setEditing("new")}>{t("webhooks.action.new")}</Button>}
      />

      <PageBody>
      {rows === null ? (
        <div className="hx-loadwrap">
          <Spinner size={28} label={t("webhooks.loading")} />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("webhooks.empty.title")}
          message={t("webhooks.empty.message")}
          action={<Button variant="primary" onClick={() => setEditing("new")}>{t("webhooks.action.new")}</Button>}
        />
      ) : (
        <>
          {/* desktop table */}
          <div className="hx-card hx-show-desktop">
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr><th>{t("webhooks.th.name")}</th><th>{t("webhooks.th.endpoint")}</th><th>{t("webhooks.th.events")}</th><th>{t("webhooks.th.secret")}</th><th>{t("webhooks.th.status")}</th><th className="hx-col-actions" aria-label={t("webhooks.th.actions")} /></tr>
                </thead>
                <tbody>
                  {rows.map((w) => (
                    <tr key={w.id}>
                      <td>
                        <button type="button" className="hx-textbtn" onClick={() => setEditing(w)}>{w.name?.trim() || "—"}</button>
                      </td>
                      <td><span className="hx-mono hx-muted">{w.url}</span></td>
                      <td>{w.eventTypes?.trim() ? w.eventTypes : <span className="hx-faint">{t("webhooks.allEvents")}</span>}</td>
                      <td>{secretBadge(w)}</td>
                      <td>{statusBadge(w)}</td>
                      <td className="hx-cell-right">
                        <RowMenu items={menuItems(w)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* mobile cards */}
          <div className="hx-cards hx-show-mobile">
            {rows.map((w) => (
              <div className="hx-rowcard" key={w.id}>
                <div className="hx-rowcard__head">
                  <div className="hx-rowcard__grow">
                    <div className="hx-rowcard__title hx-namecell">
                      <button type="button" className="hx-textbtn" onClick={() => setEditing(w)}>{w.name?.trim() || "—"}</button>
                      <span className="hx-badges">{secretBadge(w)}{statusBadge(w)}</span>
                    </div>
                    <div className="hx-rowcard__sub hx-mono">{w.url}</div>
                    <div className="hx-rowcard__sub">{w.eventTypes?.trim() ? w.eventTypes : t("webhooks.allEvents")}</div>
                  </div>
                  <div className="hx-rowcard__actions">
                    <RowMenu items={menuItems(w)} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      </PageBody>

      <Modal open={editing !== null} title={editing === "new" ? t("webhooks.modal.new") : t("webhooks.modal.edit")} onClose={() => setEditing(null)} width={540}>
        {editing !== null && (
          <WebhookForm
            initial={editing === "new" ? null : editing}
            onCancel={() => setEditing(null)}
            onSubmit={(body) => submit(editing === "new" ? null : editing.id, body)}
          />
        )}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("webhooks.confirm.title")}
        message={t("webhooks.confirm.message", { url: toDelete?.url ?? "" })}
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

function WebhookForm({ initial, onSubmit, onCancel }: { initial: Webhook | null; onSubmit: (b: WebhookWrite) => void; onCancel: () => void }) {
  const { t } = useT();
  const [name, setName] = React.useState(initial?.name ?? "");
  const [url, setUrl] = React.useState(initial?.url ?? "");
  const [secret, setSecret] = React.useState("");
  const [eventTypes, setEventTypes] = React.useState(initial?.eventTypes ?? "");
  const [enabled, setEnabled] = React.useState(initial?.enabled ?? true);
  const [attempted, setAttempted] = React.useState(false);
  const errors = validateWebhook({ url });

  const save = () => {
    setAttempted(true);
    if (errors.length) return;
    onSubmit({ name: name.trim() || null, url: url.trim(), secret: secret.trim() || undefined, eventTypes: eventTypes.trim(), enabled });
  };

  return (
    <div>
      <FormField label={t("webhooks.form.name.label")} hint={t("webhooks.form.name.hint")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("webhooks.form.name.placeholder")} />
      </FormField>
      <FormField label={t("webhooks.form.url.label")} required error={attempted && errors.includes("url") ? t("webhooks.form.url.error") : undefined}>
        <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={t("webhooks.form.url.placeholder")} />
      </FormField>
      <FormField label={t("webhooks.form.secret.label")} hint={initial?.secretSet ? t("webhooks.form.secret.hintSet") : t("webhooks.form.secret.hint")}>
        <Input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={initial?.secretSet ? t("webhooks.form.secret.placeholderSet") : t("webhooks.form.secret.placeholder")} />
      </FormField>
      <FormField label={t("webhooks.form.events.label")} hint={t("webhooks.form.events.hint")}>
        <Input value={eventTypes} onChange={(e) => setEventTypes(e.target.value)} placeholder={t("webhooks.form.events.placeholder")} />
      </FormField>
      <FormField label={t("webhooks.form.status.label")}>
        <Switch checked={enabled} onChange={setEnabled} label={t("webhooks.form.enabled")} />
      </FormField>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{initial ? t("webhooks.form.save") : t("webhooks.form.create")}</Button>
      </div>
    </div>
  );
}
