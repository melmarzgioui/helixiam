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
import { AccountApi, AccountIdentity } from "./api";
import type { Note } from "./AccountApp";
import { useT } from "../i18n/LocaleContext";

/**
 * Helix IAM B9: the account "Connected accounts" tab — the identity providers (Google, DigiD, an
 * upstream OIDC/SAML IdP, …) the signed-in user can sign in through. Disconnecting removes that login
 * method; the local account and any other linked logins are untouched.
 */
export function IdentitiesTab({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [identities, setIdentities] = React.useState<AccountIdentity[] | null>(null);
  const [confirm, setConfirm] = React.useState<AccountIdentity | null>(null);
  const [busy, setBusy] = React.useState(false);

  const reload = React.useCallback(() => {
    setIdentities(null);
    api.listIdentities()
      .then(setIdentities)
      .catch((e) => { setIdentities([]); onNote({ tone: "error", title: t("account.identities.loadError"), message: String(e.message ?? e) }); });
  }, [api, onNote, t]);
  React.useEffect(reload, [reload]);

  const unlink = (i: AccountIdentity) => {
    setBusy(true);
    api.unlinkIdentity(i.idpAlias)
      .then(() => {
        setIdentities((prev) => (prev ?? []).filter((x) => x.idpAlias !== i.idpAlias));
        onNote({ tone: "success", title: t("account.identities.disconnectedToast"), message: i.idpAlias });
      })
      .catch((e) => onNote({ tone: "error", title: t("account.identities.disconnectError"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setConfirm(null); });
  };

  if (identities === null) {
    return <div className="hx-loadwrap"><Spinner size={24} label={t("account.identities.loading")} /></div>;
  }

  return (
    <Card title={t("account.identities.card.title")} subtitle={t("account.identities.card.subtitle")}>
      {identities.length === 0 ? (
        <EmptyState title={t("account.identities.empty")} />
      ) : (
        <div className="hx-acctlist">
          {identities.map((i) => (
            <div key={i.idpAlias} className="hx-card hx-acctrow">
              <div className="hx-acctrow__body hx-acctrow__body--center">
                <div className="hx-acctrow__main">
                  <div className="hx-acctrow__title hx-acctrow__title--row">
                    {i.idpAlias}<Badge tone="accent">{t("account.identities.connectedBadge")}</Badge>
                  </div>
                  <div className="hx-acctrow__meta hx-acctrow__meta--ellipsis">
                    {i.externalSubject}
                  </div>
                  <div className="hx-acctrow__sub">
                    {i.linkedAt ? t("account.identities.connectedAt", { date: new Date(i.linkedAt).toLocaleString() }) : t("account.identities.connected")}
                  </div>
                </div>
                <Button variant="ghost" onClick={() => setConfirm(i)} className="hx-acctrow__action">{t("account.identities.disconnect")}</Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={confirm !== null}
        title={t("account.identities.disconnectDialog.title")}
        message={confirm ? t("account.identities.disconnectDialog.message", { provider: confirm.idpAlias }) : ""}
        confirmLabel={busy ? t("account.identities.disconnecting") : t("account.identities.disconnect")}
        onConfirm={() => confirm && unlink(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </Card>
  );
}
