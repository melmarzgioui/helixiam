import React from "react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { ConfirmDialog } from "../components/Modal";
import { AccountApi, GdprConsentRecord } from "./api";
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
    <div style={{ display: "grid", gap: "1.2rem" }}>
      <Card title={t("account.privacy.export.title")} subtitle={t("account.privacy.export.subtitle")}>
        <p style={{ color: "var(--fg-muted)", fontSize: ".9rem", margin: "0 0 1rem" }}>
          {t("account.privacy.export.description")}
        </p>
        <Button variant="primary" onClick={download} disabled={exporting}>
          {exporting ? t("account.privacy.preparing") : t("account.privacy.downloadButton")}
        </Button>
      </Card>

      <Card title={t("account.privacy.history.title")} subtitle={t("account.privacy.history.subtitle")}>
        {consents === null ? (
          <div style={{ padding: "2rem", display: "flex", justifyContent: "center" }}>
            <Spinner size={24} label={t("account.privacy.loadingHistory")} />
          </div>
        ) : consents.length === 0 ? (
          <p style={{ color: "var(--fg-muted)", fontSize: ".9rem" }}>{t("account.privacy.historyEmpty")}</p>
        ) : (
          <div style={{ display: "grid", gap: ".7rem" }}>
            {consents.map((c) => {
              const active = c.withdrawnAt === null;
              return (
                <div key={c.id} className="hx-card" style={{ padding: ".9rem 1.1rem", opacity: active ? 1 : 0.7 }}>
                  <div style={{ display: "flex", alignItems: "flex-start", gap: "1rem" }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: ".5rem" }}>
                        <span style={{ fontWeight: 600 }}>{c.clientId}</span>
                        <Badge tone={active ? "accent" : "neutral"}>{active ? t("account.privacy.statusActive") : t("account.privacy.statusWithdrawn")}</Badge>
                      </div>
                      <div style={{ color: "var(--fg-muted)", fontSize: ".8rem" }}>
                        {c.grantedAt ? t("account.privacy.grantedAt", { date: new Date(c.grantedAt).toLocaleString() }) : t("account.privacy.granted")}
                        {c.withdrawnAt ? " " + t("account.privacy.withdrawnAt", { date: new Date(c.withdrawnAt).toLocaleString() }) : ""}
                      </div>
                      <div style={{ marginTop: ".5rem", display: "flex", flexWrap: "wrap", gap: ".35rem" }}>
                        {c.scopes.length === 0
                          ? <span style={{ color: "var(--fg-faint)", fontSize: ".8rem" }}>{t("account.privacy.noScopes")}</span>
                          : c.scopes.map((s) => <Badge key={s} tone="neutral">{s}</Badge>)}
                      </div>
                    </div>
                    {active && activeClients.has(c.clientId) && (
                      <Button variant="ghost" onClick={() => setConfirm(c)} style={{ padding: ".4rem .85rem", flexShrink: 0 }}>
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
