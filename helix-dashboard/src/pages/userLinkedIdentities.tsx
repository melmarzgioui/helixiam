/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Section } from "../components/Page";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { Alert } from "../components/Alert";
import { ConfirmDialog } from "../components/Modal";
import { FederatedIdentityApi, LinkedIdentity, linkActions, provenanceKey } from "../api/federatedIdentities";
import type { Note } from "./UsersPage";
import { useT } from "../i18n/LocaleContext";

/**
 * Round 6: a user's linked identities, with how each link was made. A realm admin can confirm a link (it may then sign
 * in the user while they are an administrator) or revoke trust in it (it never does).
 */
export function UserLinkedIdentities({ api, realmId, userId, onNote }: {
  api: FederatedIdentityApi; realmId: string; userId: string; onNote: (n: Note) => void;
}) {
  const { t } = useT();
  const [links, setLinks] = React.useState<LinkedIdentity[] | null>(null);
  const [canManage, setCanManage] = React.useState(false);
  const [pending, setPending] = React.useState<{ link: LinkedIdentity; action: "confirm" | "revoke" } | null>(null);
  const [busy, setBusy] = React.useState(false);

  const reload = React.useCallback(() => {
    setLinks(null);
    api.list(realmId, userId)
      .then((r) => { setLinks(r.identities); setCanManage(r.canManageTrust); })
      .catch((e) => { setLinks([]); onNote({ tone: "error", title: t("userIdentities.load.error"), message: String(e.message ?? e) }); });
  }, [api, realmId, userId, onNote, t]);
  React.useEffect(reload, [reload]);

  const run = () => {
    if (!pending) return;
    setBusy(true);
    const call = pending.action === "confirm"
      ? api.confirm(realmId, userId, pending.link.idpAlias)
      : api.revokeTrust(realmId, userId, pending.link.idpAlias);
    call
      .then(() => {
        onNote({ tone: "success", title: t(pending.action === "confirm" ? "userIdentities.confirmed" : "userIdentities.revoked"), message: pending.link.idpAlias });
        reload();
      })
      .catch((e) => onNote({ tone: "error", title: t("userIdentities.action.error"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setPending(null); });
  };

  return (
    <Section title={t("userIdentities.title")} description={t("userIdentities.description")}>
      {links === null ? (
        <div className="hx-loadwrap"><Spinner size={24} label={t("userIdentities.loading")} /></div>
      ) : links.length === 0 ? (
        <p className="hx-muted">{t("userIdentities.empty")}</p>
      ) : (
        <>
          {!canManage && <Alert tone="info">{t("userIdentities.realmAdminOnly")}</Alert>}
          <div className="hx-cards">
            {links.map((l) => (
              <div key={`${l.idpAlias}|${l.externalSubject}`} className="hx-rowcard">
                <div className="hx-rowcard__head">
                  <div className="hx-rowcard__grow">
                    <div className="hx-rowcard__title">{l.idpAlias}</div>
                    <div className="hx-badges">
                      <Badge tone="neutral">{t(provenanceKey(l.createdVia))}</Badge>
                      <Badge tone={l.trustedForAdmins ? "success" : "warning"}>
                        {t(l.trustedForAdmins ? "userIdentities.trusted" : "userIdentities.untrusted")}
                      </Badge>
                    </div>
                    <div className="hx-rowcard__sub hx-mono">{l.externalSubject}</div>
                  </div>
                  <div className="hx-rowcard__actions">
                    {linkActions(l, canManage).map((a) => (
                      <Button key={a} variant="ghost" className={a === "revoke" ? "hx-btn--danger" : undefined}
                              disabled={busy} onClick={() => setPending({ link: l, action: a })}>
                        {t(a === "confirm" ? "userIdentities.confirm" : "userIdentities.revoke")}
                      </Button>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      <ConfirmDialog
        open={pending !== null}
        title={t(pending?.action === "revoke" ? "userIdentities.revoke.dialog.title" : "userIdentities.confirm.dialog.title")}
        message={pending ? t(pending.action === "revoke" ? "userIdentities.revoke.dialog.message" : "userIdentities.confirm.dialog.message", { provider: pending.link.idpAlias }) : ""}
        confirmLabel={busy ? t("userIdentities.working") : t(pending?.action === "revoke" ? "userIdentities.revoke" : "userIdentities.confirm")}
        onConfirm={run}
        onCancel={() => setPending(null)}
      />
    </Section>
  );
}
