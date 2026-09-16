/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { RealmKey, RealmKeyApi } from "../api/keys";
import { useT } from "../i18n/LocaleContext";

export interface RealmKeysPageProps {
  api: RealmKeyApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

const STATUS_TONE: Record<string, "success" | "warning" | "neutral"> = {
  ACTIVE: "success",
  ROTATED: "warning",
  RETIRED: "neutral",
};

/**
 * Helix IAM B8: per-realm JWT signing keys. The ACTIVE key signs new tokens; rotating it
 * (zero-downtime) demotes it to ROTATED — still published in the JWKS so already-issued tokens keep
 * verifying — and generates a fresh ACTIVE key. A ROTATED key can be retired once the overlap window
 * has passed, dropping it from the JWKS. Only public material is ever shown.
 */
export function RealmKeysPage({ api, realmId }: RealmKeysPageProps) {
  const { t } = useT();
  const [keys, setKeys] = React.useState<RealmKey[] | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);
  const [rotating, setRotating] = React.useState(false);
  const [confirmRotate, setConfirmRotate] = React.useState(false);
  const [toRetire, setToRetire] = React.useState<RealmKey | null>(null);
  const [viewKey, setViewKey] = React.useState<RealmKey | null>(null);

  const reload = React.useCallback(() => {
    setKeys(null);
    api.list(realmId)
      .then(setKeys)
      .catch((e) => { setKeys([]); setNote({ tone: "error", title: t("realmKeys.toast.loadError"), message: String(e.message ?? e) }); });
  }, [api, realmId]);

  React.useEffect(reload, [reload]);

  const doRotate = () => {
    setConfirmRotate(false);
    setRotating(true);
    api.rotate(realmId)
      .then((k) => { setNote({ tone: "success", title: t("realmKeys.toast.rotated"), message: t("realmKeys.toast.rotated.message", { kid: k.keyId.slice(0, 12) }) }); reload(); })
      .catch((e) => setNote({ tone: "error", title: t("realmKeys.toast.rotateFailed"), message: String(e.message ?? e) }))
      .finally(() => setRotating(false));
  };

  const doRetire = () => {
    const key = toRetire;
    setToRetire(null);
    if (!key) return;
    api.retire(realmId, key.keyId)
      .then(() => { setNote({ tone: "success", title: t("realmKeys.toast.retired"), message: t("realmKeys.toast.retired.message") }); reload(); })
      .catch((e) => setNote({ tone: "error", title: t("realmKeys.toast.retireFailed"), message: String(e.message ?? e) }));
  };

  const fmt = (ms: number | null) => (ms ? new Date(ms).toISOString().replace("T", " ").replace(/\..*$/, "") : "—");

  return (
    <Page>
      <PageHeader
        title={t("realmKeys.title")}
        description={t("realmKeys.description", { realmId })}
        actions={<>
          <Button variant="ghost" onClick={reload} disabled={keys === null}>{t("realmKeys.action.refresh")}</Button>
          <Button variant="primary" onClick={() => setConfirmRotate(true)} disabled={rotating || keys === null}>
            {rotating ? t("realmKeys.action.rotating") : t("realmKeys.action.rotate")}
          </Button>
        </>}
      />

      <PageBody>
      {keys === null ? (
        <div className="hx-loadwrap">
          <Spinner size={28} label={t("realmKeys.loading")} />
        </div>
      ) : keys.length === 0 ? (
        <EmptyState
          title={t("realmKeys.empty.title")}
          message={t("realmKeys.empty.message")}
        />
      ) : (
        <>
          {/* desktop table */}
          <div className="hx-card hx-show-desktop">
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr><th>{t("realmKeys.col.kid")}</th><th>{t("realmKeys.col.algorithm")}</th><th>{t("realmKeys.col.status")}</th><th>{t("realmKeys.col.created")}</th><th>{t("realmKeys.col.rotated")}</th><th>{t("realmKeys.col.publicKey")}</th><th className="hx-col-actions" aria-label={t("realmKeys.col.actions")} /></tr>
                </thead>
                <tbody>
                  {keys.map((k) => (
                    <tr key={k.keyId}>
                      <td><span className="hx-conn__alias" title={k.keyId}>{k.keyId}</span></td>
                      <td>{k.algorithm}</td>
                      <td><Badge tone={STATUS_TONE[k.status] ?? "neutral"}>{k.status}</Badge></td>
                      <td className="hx-muted">{fmt(k.createdAt)}</td>
                      <td className="hx-muted">{fmt(k.rotatedAt)}</td>
                      <td>{k.publicKey ? <Button variant="ghost" onClick={() => setViewKey(k)}>{t("realmKeys.action.view")}</Button> : "—"}</td>
                      <td className="hx-cell-right">
                        {k.status === "ROTATED" && <Button variant="ghost" onClick={() => setToRetire(k)}>{t("realmKeys.action.retire")}</Button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* mobile cards */}
          <div className="hx-cards hx-show-mobile">
            {keys.map((k) => (
              <div className="hx-rowcard" key={k.keyId}>
                <div className="hx-rowcard__head">
                  <div className="hx-rowcard__grow">
                    <div className="hx-rowcard__title hx-namecell">
                      <Badge tone={STATUS_TONE[k.status] ?? "neutral"}>{k.status}</Badge>{k.algorithm}
                    </div>
                    <div className="hx-rowcard__sub hx-mono" title={k.keyId}>{k.keyId}</div>
                  </div>
                  <div className="hx-rowcard__actions">
                    {k.publicKey && <Button variant="ghost" onClick={() => setViewKey(k)}>{t("realmKeys.action.view")}</Button>}
                    {k.status === "ROTATED" && <Button variant="ghost" onClick={() => setToRetire(k)}>{t("realmKeys.action.retire")}</Button>}
                  </div>
                </div>
                <div className="hx-rowcard__fields">
                  <div className="hx-rowcard__field">
                    <span className="hx-rowcard__label">{t("realmKeys.col.created")}</span>
                    <span className="hx-rowcard__value">{fmt(k.createdAt)}</span>
                  </div>
                  <div className="hx-rowcard__field">
                    <span className="hx-rowcard__label">{t("realmKeys.col.rotated")}</span>
                    <span className="hx-rowcard__value">{fmt(k.rotatedAt)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      </PageBody>

      <ConfirmDialog
        open={confirmRotate}
        title={t("realmKeys.confirm.rotate.title")}
        message={t("realmKeys.confirm.rotate.message")}
        confirmLabel={t("realmKeys.confirm.rotate.label")}
        onConfirm={doRotate}
        onCancel={() => setConfirmRotate(false)}
      />
      <ConfirmDialog
        open={toRetire !== null}
        title={t("realmKeys.confirm.retire.title")}
        message={t("realmKeys.confirm.retire.message", { kid: toRetire?.keyId.slice(0, 12) ?? "" })}
        confirmLabel={t("realmKeys.confirm.retire.label")}
        onConfirm={doRetire}
        onCancel={() => setToRetire(null)}
      />
      <Modal open={viewKey !== null} title={t("realmKeys.modal.publicKey.title")} onClose={() => setViewKey(null)} width={620}>
        <p className="hx-help">
          {t("realmKeys.modal.publicKey.body", { algorithm: viewKey?.algorithm ?? "" })}
        </p>
        <pre className="hx-codeblock">{viewKey?.publicKey}</pre>
      </Modal>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}
