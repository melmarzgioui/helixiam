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
import { AccountApi, GdprConsentRecord } from "./api";
import { clientLabel } from "../api/clients";
import type { Note } from "./AccountApp";
import { useT } from "../i18n/LocaleContext";

/**
 * Helix IAM (6) — GDPR / Privacy self-service tab. Lets the signed-in user exercise their data-subject
 * rights: download a complete copy of their data (Art. 15/20) and view + withdraw their consent ledger
 * (Art. 7). Erasure (Art. 17) is intentionally an admin-only action and not surfaced here.
 */
export function PrivacyTab({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [consents, setConsents] = React.useState<GdprConsentRecord[] | null>(null);
  const [confirm, setConfirm] = React.useState<GdprConsentRecord | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [exporting, setExporting] = React.useState(false);

  const reload = React.useCallback(() => {
    setConsents(null);
    api.gdprConsents()
      .then(setConsents)
      .catch((e) => { setConsents([]); onNote({ tone: "error", title: t("account.privacy.loadError"), message: String(e.message ?? e) }); });
  }, [api, onNote, t]);
  React.useEffect(reload, [reload]);

  const download = () => {
    setExporting(true);
    api.gdprExport()
      .then((data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `my-data-${data.userId ?? "export"}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        onNote({ tone: "success", title: t("account.privacy.exportedToast"), message: t("account.privacy.exportedMessage") });
      })
      .catch((e) => onNote({ tone: "error", title: t("account.privacy.exportError"), message: String(e.message ?? e) }))
      .finally(() => setExporting(false));
  };

  const withdraw = (c: GdprConsentRecord) => {
    setBusy(true);
    api.gdprWithdrawConsent(c.clientId)
      .then(() => { onNote({ tone: "success", title: t("account.privacy.withdrawnToast"), message: c.clientId }); reload(); })
      .catch((e) => onNote({ tone: "error", title: t("account.privacy.withdrawError"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setConfirm(null); });
  };

  // One active row per client drives whether a "Withdraw" action is offered.
  const activeClients = new Set((consents ?? []).filter((c) => c.withdrawnAt === null).map((c) => c.clientId));

  return (
    <div className="hx-stack">
      <Card title={t("account.privacy.export.title")} subtitle={t("account.privacy.export.subtitle")}>
        <p className="hx-help hx-mb-4">
          {t("account.privacy.export.description")}
        </p>
        <Button variant="primary" onClick={download} disabled={exporting}>
          {exporting ? t("account.privacy.preparing") : t("account.privacy.downloadButton")}
        </Button>
      </Card>

      <Card title={t("account.privacy.history.title")} subtitle={t("account.privacy.history.subtitle")}>
        {consents === null ? (
          <div className="hx-loadwrap">
            <Spinner size={24} label={t("account.privacy.loadingHistory")} />
          </div>
        ) : consents.length === 0 ? (
          <EmptyState title={t("account.privacy.historyEmpty")} message={t("account.privacy.historyEmpty.msg")} />
        ) : (
          <div className="hx-acctlist">
            {consents.map((c) => {
              const active = c.withdrawnAt === null;
              return (
                <div key={c.id} className={`hx-card hx-acctrow${active ? "" : " hx-acctrow--dim"}`}>
                  <div className="hx-acctrow__body">
                    <div className="hx-acctrow__main">
                      <div className="hx-acctrow__title--row">
                        <span className="hx-acctrow__title">{clientLabel({ clientId: c.clientId })}</span>
                        <Badge tone={active ? "accent" : "neutral"}>{active ? t("account.privacy.statusActive") : t("account.privacy.statusWithdrawn")}</Badge>
                      </div>
                      <div className="hx-acctrow__meta">
                        {c.grantedAt ? t("account.privacy.grantedAt", { date: new Date(c.grantedAt).toLocaleString() }) : t("account.privacy.granted")}
                        {c.withdrawnAt ? " " + t("account.privacy.withdrawnAt", { date: new Date(c.withdrawnAt).toLocaleString() }) : ""}
                      </div>
                      <div className="hx-acctrow__badges">
                        {c.scopes.length === 0
                          ? <span className="hx-acctrow__empty">{t("account.privacy.noScopes")}</span>
                          : c.scopes.map((s) => <Badge key={s} tone="neutral">{s}</Badge>)}
                      </div>
                    </div>
                    {active && activeClients.has(c.clientId) && (
                      <Button variant="ghost" onClick={() => setConfirm(c)} className="hx-acctrow__action">
                        {t("account.privacy.withdrawConsent")}
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={confirm !== null}
        title={t("account.privacy.withdrawDialog.title")}
        message={confirm ? t("account.privacy.withdrawDialog.message", { clientId: confirm.clientId }) : ""}
        confirmLabel={busy ? t("account.privacy.withdrawing") : t("account.privacy.withdrawConsent")}
        onConfirm={() => confirm && withdraw(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
}
