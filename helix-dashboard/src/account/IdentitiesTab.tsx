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
import type { Note } from "./AccountApp";
import { useT } from "../i18n/LocaleContext";
import { isSameSitePath, validateLinkChoice } from "./validation";
import { subjectLabel } from "../api/federatedIdentities";

/** One row of the merged list: a provider of the realm (or a linked one it no longer offers) and its links. */
export interface IdentityRow {
  alias: string;
  displayName: string;
  /** Whether the realm offers it for linking here. */
  linkable: boolean;
  links: AccountIdentity[];
}

/**
 * Round 6: one list of the realm's linkable providers and the user's links, by provider display name. A linked
 * provider the realm no longer offers is still listed (by alias) so it can be disconnected.
 */
export function mergeIdentityRows(providers: LinkableProvider[], identities: AccountIdentity[]): IdentityRow[] {
  const rows: IdentityRow[] = providers.map((p) => ({
    alias: p.alias, displayName: p.displayName || p.alias, linkable: true,
    links: identities.filter((i) => i.idpAlias === p.alias),
  }));
  for (const i of identities) {
    if (!rows.some((r) => r.alias === i.idpAlias)) {
      rows.push({ alias: i.idpAlias, displayName: i.idpAlias, linkable: false, links: identities.filter((x) => x.idpAlias === i.idpAlias) });
    }
  }
  return rows;
}

/**
 * Helix IAM B9 + round 6: Connected accounts. Each provider of the realm with its state: Link (a fresh sign-in here,
 * then the provider's sign-in), Confirm again (prove the link is yours, which administrators need for links made
 * automatically) and Disconnect (with a confirmation). The local account and other sign-in methods are untouched.
 */
export function IdentitiesTab({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [rows, setRows] = React.useState<IdentityRow[] | null>(null);
  const [confirm, setConfirm] = React.useState<IdentityRow | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);

  const reload = React.useCallback(() => {
    setRows(null);
    Promise.all([
      api.listIdentities(),
      api.listLinkableProviders ? api.listLinkableProviders().catch(() => [] as LinkableProvider[]) : Promise.resolve([] as LinkableProvider[]),
    ])
      .then(([identities, providers]) => setRows(mergeIdentityRows(providers, identities)))
      .catch((e) => { setRows([]); onNote({ tone: "error", title: t("account.identities.loadError"), message: String(e.message ?? e) }); });
  }, [api, onNote, t]);
  React.useEffect(reload, [reload]);

  const link = (row: IdentityRow) => {
    const error = validateLinkChoice(row.alias, (rows ?? []).filter((r) => r.linkable).map((r) => r.alias));
    if (error || !api.startLink) {
      onNote({ tone: "error", title: t(error ?? "account.identities.link.error") });
      return;
    }
    setBusy(row.alias);
    api.startLink(row.alias)
      .then((r) => {
        if (!isSameSitePath(r.location)) throw new Error(t("account.identities.link.error"));
        window.location.assign(r.location);
      })
      .catch((e) => { setBusy(null); onNote({ tone: "error", title: t("account.identities.link.error"), message: String(e.message ?? e) }); });
  };

  const unlink = (row: IdentityRow) => {
    setBusy(row.alias);
    api.unlinkIdentity(row.alias)
      .then(() => { onNote({ tone: "success", title: t("account.identities.disconnectedToast"), message: row.displayName }); reload(); })
      .catch((e) => onNote({ tone: "error", title: t("account.identities.disconnectError"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(null); setConfirm(null); });
  };

  if (rows === null) {
    return <div className="hx-loadwrap"><Spinner size={24} label={t("account.identities.loading")} /></div>;
  }

  return (
    <Card title={t("account.identities.card.title")} subtitle={t("account.identities.available.subtitle")}>
      {rows.length === 0 ? (
        <EmptyState title={t("account.identities.empty")} message={t("account.identities.empty.msg")} />
      ) : (
        <div className="hx-acctlist">
          {rows.map((r) => (
            <div key={r.alias} className="hx-card hx-acctrow">
              <div className="hx-linkrow">
                <div className="hx-linkrow__main">
                  <div className="hx-acctrow__title hx-acctrow__title--row">
                    <span className="hx-linkrow__alias" title={r.displayName}>{r.displayName}</span>
                    {r.links.length > 0
                      ? <Badge tone="accent">{t("account.identities.connectedBadge")}</Badge>
                      : <Badge tone="neutral">{t("account.identities.notConnected")}</Badge>}
                  </div>
                  {r.links.map((l) => (
                    <div key={l.externalSubject} className="hx-linkrow__hint">
                      <span className="hx-mono">{subjectLabel(l)}</span>
                      {" · "}
                      {l.linkedAt ? t("account.identities.connectedAt", { date: new Date(l.linkedAt).toLocaleString() }) : t("account.identities.connected")}
                    </div>
                  ))}
                  {r.links.length > 0 && r.linkable && (
                    <div className="hx-linkrow__hint">{t("account.identities.relink.hint")}</div>
                  )}
                </div>
                <div className="hx-linkrow__actions">
                  {r.linkable && (
                    <Button variant={r.links.length > 0 ? "ghost" : "primary"} disabled={busy !== null} onClick={() => link(r)}
                            aria-label={t("account.identities.linkNamed", { provider: r.displayName })}>
                      {busy === r.alias ? <Spinner size={14} /> : t(r.links.length > 0 ? "account.identities.relink" : "account.identities.link")}
                    </Button>
                  )}
                  {r.links.length > 0 && (
                    <Button variant="danger-outline" disabled={busy !== null} onClick={() => setConfirm(r)}>
                      {t("account.identities.disconnect")}
                    </Button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={confirm !== null}
        title={t("account.identities.disconnectDialog.title")}
        message={confirm ? t("account.identities.disconnectDialog.message", { provider: confirm.displayName }) : ""}
        confirmLabel={busy ? t("account.identities.disconnecting") : t("account.identities.disconnect")}
        onConfirm={() => confirm && unlink(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </Card>
  );
}
