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
import { AccountApi, AccountSession } from "./api";
import { clientLabel } from "../api/clients";
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
    return <div className="hx-loadwrap"><Spinner size={24} label={t("account.sessions.loading")} /></div>;
  }

  return (
    <Card title={t("account.sessions.card.title")} subtitle={t("account.sessions.card.subtitle")}>
      {sessions.length === 0 ? (
        <EmptyState title={t("account.sessions.empty")} message={t("account.sessions.empty.msg")} />
      ) : (
        <div className="hx-acctlist">
          {sessions.map((s) => (
            <div key={s.ssoSessionId} className="hx-card hx-acctrow">
              <div className="hx-acctrow__body">
                <div className="hx-acctrow__main">
                  <div className="hx-acctrow__title">{t("account.sessions.browserSession")}</div>
                  <div className="hx-acctrow__meta">
                    {s.issuedAt ? t("account.sessions.startedAt", { date: new Date(s.issuedAt).toLocaleString() }) : t("account.sessions.active")}
                  </div>
                  <div className="hx-acctrow__badges">
                    {s.clients.length === 0
                      ? <span className="hx-acctrow__empty">{t("account.sessions.noApplications")}</span>
                      : s.clients.map((c) => <Badge key={c.clientId} tone="neutral">{clientLabel({ clientId: c.clientId })}</Badge>)}
                  </div>
                </div>
                <Button variant="ghost" onClick={() => setConfirm(s)} className="hx-acctrow__action">{t("account.sessions.signOut")}</Button>
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
