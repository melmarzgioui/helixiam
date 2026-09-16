import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { RowMenu } from "../components/RowMenu";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { ProviderLogo, ProviderKind } from "../components/ProviderLogo";
import { ProviderWizard } from "../components/ProviderWizard";
import { findProviderType } from "../components/providerCatalog";
import { IdentityProviderApi, IdentityProviderConfig, toRequest, fromConfig } from "../api/client";
import { useT } from "../i18n/LocaleContext";

export interface ConnectionsPageProps {
  api: IdentityProviderApi;
  realmId: string;
  /** Page heading (defaults to the Identity-providers copy). */
  title?: string;
  subtitle?: React.ReactNode;
  /** Primary button label. */
  addLabel?: string;
  /** When set, only providers whose protocol is in this list are shown (e.g. LDAP-only, eID-only). */
  protocols?: string[];
  /** Optional content rendered above the table (e.g. the eID level-of-assurance legend). */
  aboveContent?: React.ReactNode;
  /** Empty-state copy. */
  emptyTitle?: string;
  emptyMessage?: string;
  /** When provided, a row (or "Edit") navigates to a full detail page instead of opening the edit modal. */
  onOpen?: (alias: string) => void;
}

interface Note {
  tone: ToastTone;
  title: string;
  message?: string;
}

/** E8.4/E8.3: the live "Identity providers" screen — premium + responsive. */
export function ConnectionsPage({ api, realmId, title, subtitle, addLabel, protocols, aboveContent, emptyTitle, emptyMessage, onOpen }: ConnectionsPageProps) {
  const { t } = useT();
  const [allRows, setAllRows] = React.useState<IdentityProviderConfig[] | null>(null);
  const rows = allRows == null ? null : (protocols ? allRows.filter((c) => protocols.includes(c.protocol)) : allRows);
  const setRows = setAllRows;
  const [wizardOpen, setWizardOpen] = React.useState(false);
  const [toEdit, setToEdit] = React.useState<IdentityProviderConfig | null>(null);
  const [toDelete, setToDelete] = React.useState<IdentityProviderConfig | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);

  const editorOpen = wizardOpen || toEdit !== null;
  const closeEditor = () => { setWizardOpen(false); setToEdit(null); };
  // When a detail route is wired (onOpen), editing happens on a full page; otherwise fall back to the modal.
  const editConn = (c: IdentityProviderConfig) => (onOpen ? onOpen(c.alias) : setToEdit(c));

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => {
      setRows([]);
      setNote({ tone: "error", title: t("connections.errLoad"), message: String(e.message ?? e) });
    });
  }, [api, realmId]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(reload, [reload]);

  const submitWizard = async (result: Parameters<NonNullable<React.ComponentProps<typeof ProviderWizard>["onComplete"]>>[0]) => {
    setBusy(true);
    try {
      if (toEdit) {
        await api.update(realmId, toEdit.alias, toRequest(result));
        setNote({ tone: "success", title: t("connections.toastUpdated"), message: t("connections.toastUpdatedMsg", { name: result.displayName }) });
      } else {
        await api.create(realmId, toRequest(result));
        setNote({ tone: "success", title: t("connections.toastCreated"), message: t("connections.toastCreatedMsg", { name: result.displayName, realm: realmId }) });
      }
      closeEditor();
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("connections.errSave"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const target = toDelete;
    setToDelete(null);
    try {
      await api.remove(realmId, target.alias);
      setNote({ tone: "info", title: t("connections.toastDeleted"), message: t("connections.toastDeletedMsg", { name: target.displayName || target.alias }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("connections.errDelete"), message: String((e as Error).message ?? e) });
    }
  };

  const effectiveAddLabel = addLabel ?? t("connections.addLabel");

  return (
    <Page>
      <PageHeader
        title={title ?? t("connections.title")}
        description={subtitle ?? <>{t("connections.subtitlePrefix")} <strong>{realmId}</strong> {t("connections.subtitleSuffix")}</>}
        actions={<Button variant="primary" onClick={() => setWizardOpen(true)}>{effectiveAddLabel}</Button>}
      />

      <PageBody>
      {aboveContent}

      {rows === null ? (
        <div className="hx-loadwrap">
          <Spinner size={28} label={t("common.loading")} />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title={emptyTitle ?? t("connections.emptyTitle")}
          message={emptyMessage ?? t("connections.emptyMessage")}
          action={<Button variant="primary" onClick={() => setWizardOpen(true)}>{effectiveAddLabel}</Button>}
        />
      ) : (
        <>
          {/* desktop table */}
          <div className="hx-card hx-show-desktop">
            <div className="hx-tablescroll">
            <table className="hx-table">
              <thead>
                <tr>
                  <th>{t("connections.colConnection")}</th>
                  <th>{t("connections.colProtocol")}</th>
                  <th>{t("connections.colStatus")}</th>
                  <th className="hx-col-actions" aria-label={t("connections.actionsLabel")} />
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.alias} onClick={() => editConn(c)} className={onOpen ? "hx-row-clickable" : undefined}>
                    <td>
                      <div className="hx-conn">
                        <ProviderLogo kind={kindOf(c)} size={34} />
                        <div>
                          <div className="hx-conn__name">{c.displayName || c.alias}</div>
                          <div className="hx-conn__alias">{c.alias}</div>
                        </div>
                      </div>
                    </td>
                    <td><ProtocolTag protocol={c.protocol} /></td>
                    <td><StatusBadge enabled={c.enabled} /></td>
                    <td className="hx-cell-right" onClick={(e) => e.stopPropagation()}><RowMenu items={[
                      { label: onOpen ? t("connections.menuOpen") : t("connections.menuEdit"), onSelect: () => editConn(c) },
                      { label: t("connections.menuDelete"), danger: true, onSelect: () => setToDelete(c) },
                    ]} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </div>

          {/* mobile cards */}
          <div className="hx-cards hx-show-mobile">
            {rows.map((c) => (
              <div className={`hx-conncard${onOpen ? " hx-rowcard--clickable" : ""}`} key={c.alias} onClick={onOpen ? () => editConn(c) : undefined}>
                <ProviderLogo kind={kindOf(c)} size={38} />
                <div className="hx-conncard__body">
                  <div className="hx-conn__name">{c.displayName || c.alias}</div>
                  <div className="hx-conn__alias">{c.alias}</div>
                  <div className="hx-conncard__row">
                    <ProtocolTag protocol={c.protocol} />
                    <StatusBadge enabled={c.enabled} />
                  </div>
                </div>
                <div className="hx-rowcard__actions" onClick={(e) => e.stopPropagation()}>
                  <Button variant="ghost" onClick={() => editConn(c)}>{onOpen ? t("connections.menuOpen") : t("common.edit")}</Button>
                  <Button variant="ghost" onClick={() => setToDelete(c)}>{t("common.delete")}</Button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      </PageBody>

      <Modal open={editorOpen} title={toEdit ? t("connections.modalEditTitle") : t("connections.modalAddTitle")} onClose={closeEditor} width={720}>
        {busy ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("connections.saving")} /></div>
        ) : (
          <ProviderWizard
            key={toEdit?.alias ?? "new"}
            initial={toEdit ? fromConfig(toEdit) : undefined}
            onComplete={submitWizard}
            onCancel={closeEditor}
          />
        )}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("connections.confirmDeleteTitle")}
        message={t("connections.confirmDeleteMsg", { name: toDelete?.displayName || toDelete?.alias || "" })}
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

function kindOf(c: IdentityProviderConfig): ProviderKind {
  const known: ProviderKind[] = ["digid", "eherkenning", "eidas", "oidc", "saml", "ldap", "google", "microsoft", "github"];
  return findProviderType(c.protocol)?.kind ?? (known.includes(c.protocol as ProviderKind) ? (c.protocol as ProviderKind) : "social");
}

function ProtocolTag({ protocol }: { protocol: string }) {
  const label = protocol === "oidc" ? "OIDC" : protocol === "saml" || protocol === "ldap" ? protocol.toUpperCase() : "SAML2";
  return <Badge tone="neutral">{label}</Badge>;
}

function StatusBadge({ enabled }: { enabled: boolean }) {
  const { t } = useT();
  return <Badge tone={enabled ? "success" : "neutral"}>{enabled ? t("connections.statusEnabled") : t("connections.statusDisabled")}</Badge>;
}
