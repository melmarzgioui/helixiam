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
import { AccountApi, AccountIdentity, LinkableProvider } from "./api";
import { isSameSitePath, validateLinkChoice } from "./validation";
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
    <>
    <LinkProviders api={api} onNote={onNote} />
    <Card title={t("account.identities.card.title")} subtitle={t("account.identities.card.subtitle")}>
      {identities.length === 0 ? (
        <EmptyState title={t("account.identities.empty")} message={t("account.identities.empty.msg")} />
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
    </>
  );
}

/**
 * Round 6: link a provider of the realm. The server answers where to go: the step-up sign-in when this sign-in is not
 * recent (it then continues the link), else the provider's sign-in, which links the identity and returns to the
 * account console.
 */
function LinkProviders({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [providers, setProviders] = React.useState<LinkableProvider[] | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!api.listLinkableProviders) { setProviders([]); return; }
    api.listLinkableProviders().then(setProviders).catch(() => setProviders([]));
  }, [api]);

  const link = (alias: string) => {
    const offered = (providers ?? []).map((p) => p.alias);
    const error = validateLinkChoice(alias, offered);
    if (error || !api.startLink) {
      onNote({ tone: "error", title: t(error ?? "account.identities.link.error") });
      return;
    }
    setBusy(alias);
    api.startLink(alias)
      .then((r) => {
        if (!isSameSitePath(r.location)) throw new Error(t("account.identities.link.error"));
        window.location.assign(r.location);
      })
      .catch((e) => { setBusy(null); onNote({ tone: "error", title: t("account.identities.link.error"), message: String(e.message ?? e) }); });
  };

  if (providers === null || providers.length === 0) return null;
  return (
    <Card title={t("account.identities.available.title")} subtitle={t("account.identities.available.subtitle")}>
      <div className="hx-acctlist">
        {providers.map((p) => (
          <div key={p.alias} className="hx-card hx-acctrow">
            <div className="hx-acctrow__body hx-acctrow__body--center">
              <div className="hx-acctrow__main">
                <div className="hx-acctrow__title hx-acctrow__title--row">
                  {p.displayName}{p.linked && <Badge tone="accent">{t("account.identities.connectedBadge")}</Badge>}
                </div>
              </div>
              <Button variant="ghost" disabled={busy !== null} onClick={() => link(p.alias)} className="hx-acctrow__action"
                      aria-label={t("account.identities.linkNamed", { provider: p.displayName })}>
                {busy === p.alias ? <Spinner size={14} /> : t(p.linked ? "account.identities.relink" : "account.identities.link")}
              </Button>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}
