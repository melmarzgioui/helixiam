/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { ConfirmDialog } from "../components/Modal";
import { AccountApi, AccountConsent } from "./api";
import { clientLabel } from "../api/clients";
import type { Note } from "./AccountApp";
import { useT } from "../i18n/LocaleContext";

/**
 * Helix IAM (6): the account Applications tab — the apps the signed-in user has authorized (their consents),
 * with the scopes each was granted. Revoking withdraws consent and signs the user out of that app.
 */
export function ConsentsTab({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [consents, setConsents] = React.useState<AccountConsent[] | null>(null);
  const [confirm, setConfirm] = React.useState<AccountConsent | null>(null);
  const [busy, setBusy] = React.useState(false);

  const reload = React.useCallback(() => {
    setConsents(null);
    api.listConsents()
      .then(setConsents)
      .catch((e) => { setConsents([]); onNote({ tone: "error", title: t("account.consents.loadError"), message: String(e.message ?? e) }); });
  }, [api, onNote, t]);
  React.useEffect(reload, [reload]);

  const revoke = (c: AccountConsent) => {
    setBusy(true);
    api.revokeConsent(c.clientId)
      .then(() => {
        setConsents((prev) => (prev ?? []).filter((x) => x.clientId !== c.clientId));
        onNote({ tone: "success", title: t("account.consents.revokedToast"), message: c.clientId });
      })
      .catch((e) => onNote({ tone: "error", title: t("account.consents.revokeError"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setConfirm(null); });
  };

  if (consents === null) {
    return <div className="hx-loadwrap"><Spinner size={24} label={t("account.consents.loading")} /></div>;
  }

  return (
    <Card title={t("account.consents.card.title")} subtitle={t("account.consents.card.subtitle")}>
      {consents.length === 0 ? (
        <EmptyState title={t("account.consents.empty")} message={t("account.consents.empty.msg")} />
      ) : (
        <div className="hx-acctlist">
          {consents.map((c) => (
            <div key={c.clientId} className="hx-card hx-acctrow">
              <div className="hx-acctrow__body">
                <div className="hx-acctrow__main">
                  <div className="hx-acctrow__title">{clientLabel({ clientId: c.clientId })}</div>
                  <div className="hx-acctrow__meta">
                    {c.grantedAt ? t("account.consents.authorizedAt", { date: new Date(c.grantedAt).toLocaleString() }) : t("account.consents.authorized")}
                  </div>
                  <div className="hx-acctrow__badges">
                    {c.scopes.length === 0
                      ? <span className="hx-acctrow__empty">{t("account.consents.noScopes")}</span>
                      : c.scopes.map((s) => <Badge key={s} tone="neutral">{s}</Badge>)}
                  </div>
                </div>
                <Button variant="ghost" onClick={() => setConfirm(c)} className="hx-acctrow__action">{t("account.consents.revokeAccess")}</Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={confirm !== null}
        title={t("account.consents.revokeDialog.title")}
        message={confirm ? t("account.consents.revokeDialog.message", { clientId: confirm.clientId }) : ""}
        confirmLabel={busy ? t("account.consents.revoking") : t("account.consents.revokeAccess")}
        onConfirm={() => confirm && revoke(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </Card>
  );
}
