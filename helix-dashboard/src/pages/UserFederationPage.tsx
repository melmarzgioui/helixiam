/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

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

export interface UserFederationPageProps {
  api: IdentityProviderApi;
  realmId: string;
  /** When set, rows open the full-page connection editor (LDAP search base/filter, attributes, etc.). */
  onOpen?: (alias: string) => void;
}

interface Note {
  tone: ToastTone;
  title: string;
  message?: string;
}

/** Directory-federation protocols surfaced on this screen (LDAP / Active Directory). */
const FEDERATION_PROTOCOLS = ["ldap", "ad"];

/**
 * User federation: delegate authentication to an external user store (LDAP / Active Directory). These are
 * the same per-realm provider records as Identity providers, filtered to the directory-federation protocols,
 * managed through the same wizard + admin API (E8.2/E8.3).
 */
export function UserFederationPage({ api, realmId, onOpen }: UserFederationPageProps) {
  const { t } = useT();
  const [allRows, setAllRows] = React.useState<IdentityProviderConfig[] | null>(null);
  const rows = allRows == null ? null : allRows.filter((c) => FEDERATION_PROTOCOLS.includes(c.protocol));
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
      setNote({ tone: "error", title: t("userFederation.errLoad"), message: String(e.message ?? e) });
    });
  }, [api, realmId]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(reload, [reload]);

  const submitWizard = async (result: Parameters<NonNullable<React.ComponentProps<typeof ProviderWizard>["onComplete"]>>[0]) => {
    setBusy(true);
    try {
      if (toEdit) {
        await api.update(realmId, toEdit.alias, toRequest(result));
        setNote({ tone: "success", title: t("userFederation.toastUpdated"), message: t("userFederation.toastUpdatedMsg", { name: result.displayName }) });
      } else {
        await api.create(realmId, toRequest(result));
        setNote({ tone: "success", title: t("userFederation.toastCreated"), message: t("userFederation.toastCreatedMsg", { name: result.displayName, realm: realmId }) });
      }
      closeEditor();
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("userFederation.errSave"), message: String((e as Error).message ?? e) });
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
      setNote({ tone: "info", title: t("userFederation.toastDeleted"), message: t("userFederation.toastDeletedMsg", { name: target.displayName || target.alias }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("userFederation.errDelete"), message: String((e as Error).message ?? e) });
    }
  };

  const menuItems = (c: IdentityProviderConfig) => [
    { label: onOpen ? t("userFederation.menuOpen") : t("userFederation.menuEdit"), onSelect: () => editConn(c) },
    { label: t("userFederation.menuDelete"), danger: true, onSelect: () => setToDelete(c) },
  ];

  return (
    <Page>
      <PageHeader
        title={t("userFederation.title")}
        description={<>{t("userFederation.descriptionPrefix")} <strong>{realmId}</strong> {t("userFederation.descriptionSuffix")}</>}
        actions={<Button variant="primary" onClick={() => setWizardOpen(true)}>{t("userFederation.addLabel")}</Button>}
      />

      <PageBody>
        {rows === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("common.loading")} />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title={t("userFederation.emptyTitle")}
            message={t("userFederation.emptyMessage")}
            action={<Button variant="primary" onClick={() => setWizardOpen(true)}>{t("userFederation.addLabel")}</Button>}
          />
        ) : (
          <>
            {/* desktop table */}
            <div className="hx-card hx-show-desktop">
              <div className="hx-tablescroll">
                <table className="hx-table">
                  <thead>
                    <tr>
                      <th>{t("userFederation.colConnection")}</th>
                      <th>{t("userFederation.colProtocol")}</th>
                      <th>{t("userFederation.colStatus")}</th>
                      <th className="hx-col-actions" aria-label={t("userFederation.actionsLabel")} />
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
                        <td className="hx-cell-right" onClick={(e) => e.stopPropagation()}>
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
                  <div onClick={(e) => e.stopPropagation()}>
                    <RowMenu items={menuItems(c)} />
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </PageBody>

      <Modal open={editorOpen} title={toEdit ? t("userFederation.modalEditTitle") : t("userFederation.modalAddTitle")} onClose={closeEditor} width={720}>
        {busy ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("userFederation.saving")} /></div>
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
        title={t("userFederation.confirmDeleteTitle")}
        message={t("userFederation.confirmDeleteMsg", { name: toDelete?.displayName || toDelete?.alias || "" })}
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
  return <Badge tone={enabled ? "success" : "neutral"}>{enabled ? t("userFederation.statusEnabled") : t("userFederation.statusDisabled")}</Badge>;
}
