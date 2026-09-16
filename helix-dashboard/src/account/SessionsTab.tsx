import React from "react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { ConfirmDialog } from "../components/Modal";
import { AccountApi, AccountSession } from "./api";
import type { Note } from "./AccountApp";
import { useT } from "../i18n/LocaleContext";

/**
 * Helix IAM (6): the account Sessions tab — the signed-in user sees only their own active sign-ins (one row
 * per browser login, with the apps it touched) and can sign one out remotely (cascading Single Logout).
 */
export function SessionsTab({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [sessions, setSessions] = React.useState<AccountSession[] | null>(null);
  const [confirm, setConfirm] = React.useState<AccountSession | null>(null);
  const [busy, setBusy] = React.useState(false);

  const reload = React.useCallback(() => {
    setSessions(null);
    api.listSessions()
      .then(setSessions)
      .catch((e) => { setSessions([]); onNote({ tone: "error", title: t("account.sessions.loadError"), message: String(e.message ?? e) }); });
  }, [api, onNote, t]);
  React.useEffect(reload, [reload]);

  const revoke = (s: AccountSession) => {
    setBusy(true);
    api.revokeSession(s.ssoSessionId)
      .then(() => {
        setSessions((prev) => (prev ?? []).filter((x) => x.ssoSessionId !== s.ssoSessionId));
        onNote({ tone: "success", title: t("account.sessions.signedOutToast"), message: t("account.sessions.signedOutMessage") });
      })
      .catch((e) => onNote({ tone: "error", title: t("account.sessions.signOutError"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setConfirm(null); });
  };

  if (sessions === null) {
    return <div style={{ padding: "3rem", display: "flex", justifyContent: "center" }}><Spinner size={24} label={t("account.sessions.loading")} /></div>;
  }

  return (
    <Card title={t("account.sessions.card.title")} subtitle={t("account.sessions.card.subtitle")}>
      {sessions.length === 0 ? (
        <p style={{ color: "var(--fg-muted)", fontSize: ".9rem" }}>{t("account.sessions.empty")}</p>
      ) : (
        <div style={{ display: "grid", gap: ".7rem" }}>
          {sessions.map((s) => (
            <div key={s.ssoSessionId} className="hx-card" style={{ padding: ".9rem 1.1rem" }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "1rem" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600 }}>{t("account.sessions.browserSession")}</div>
                  <div style={{ color: "var(--fg-muted)", fontSize: ".8rem" }}>
                    {s.issuedAt ? t("account.sessions.startedAt", { date: new Date(s.issuedAt).toLocaleString() }) : t("account.sessions.active")}
                  </div>
                  <div style={{ marginTop: ".5rem", display: "flex", flexWrap: "wrap", gap: ".35rem" }}>
                    {s.clients.length === 0
                      ? <span style={{ color: "var(--fg-faint)", fontSize: ".8rem" }}>{t("account.sessions.noApplications")}</span>
                      : s.clients.map((c) => <Badge key={c.clientId} tone="neutral">{c.clientId}</Badge>)}
                  </div>
                </div>
                <Button variant="ghost" onClick={() => setConfirm(s)} style={{ padding: ".4rem .85rem", flexShrink: 0 }}>{t("account.sessions.signOut")}</Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={confirm !== null}
        title={t("account.sessions.signOutDialog.title")}
        message={t("account.sessions.signOutDialog.message")}
        confirmLabel={busy ? t("account.sessions.signingOut") : t("account.sessions.signOut")}
        onConfirm={() => confirm && revoke(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </Card>
  );
}
