/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { ConfirmDialog } from "../components/Modal";
import { AccountApi, AccountConsent } from "./api";
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
    return <div style={{ padding: "3rem", display: "flex", justifyContent: "center" }}><Spinner size={24} label={t("account.consents.loading")} /></div>;
  }

  return (
    <Card title={t("account.consents.card.title")} subtitle={t("account.consents.card.subtitle")}>
      {consents.length === 0 ? (
        <p style={{ color: "var(--fg-muted)", fontSize: ".9rem" }}>{t("account.consents.empty")}</p>
      ) : (
        <div style={{ display: "grid", gap: ".7rem" }}>
          {consents.map((c) => (
            <div key={c.clientId} className="hx-card" style={{ padding: ".9rem 1.1rem" }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "1rem" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600 }}>{c.clientId}</div>
                  <div style={{ color: "var(--fg-muted)", fontSize: ".8rem" }}>
                    {c.grantedAt ? t("account.consents.authorizedAt", { date: new Date(c.grantedAt).toLocaleString() }) : t("account.consents.authorized")}
                  </div>
                  <div style={{ marginTop: ".5rem", display: "flex", flexWrap: "wrap", gap: ".35rem" }}>
                    {c.scopes.length === 0
                      ? <span style={{ color: "var(--fg-faint)", fontSize: ".8rem" }}>{t("account.consents.noScopes")}</span>
                      : c.scopes.map((s) => <Badge key={s} tone="neutral">{s}</Badge>)}
                  </div>
                </div>
                <Button variant="ghost" onClick={() => setConfirm(c)} style={{ padding: ".4rem .85rem", flexShrink: 0 }}>{t("account.consents.revokeAccess")}</Button>
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
