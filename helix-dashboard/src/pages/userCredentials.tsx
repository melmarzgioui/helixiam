/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { ConfirmDialog } from "../components/Modal";
import { CredentialApi, CredentialSummary } from "../api/credentials";
import { useT } from "../i18n/LocaleContext";

/** The complete factor surface, in the order it presents (phishing-resistant first). */
interface FactorKind {
  type: string;
  title: string;
  blurb: string;
  icon: string;
  singleton: boolean;
}

const KINDS: Omit<FactorKind, "title" | "blurb">[] = [
  { type: "passkey", singleton: false,
    icon: "M15 7a4 4 0 11-8 0 4 4 0 018 0zM12 14v7m0-3h3M3 21a6 6 0 0112 0" },
  { type: "device", singleton: false,
    icon: "M7 4h10a1 1 0 011 1v14a1 1 0 01-1 1H7a1 1 0 01-1-1V5a1 1 0 011-1zm4 14h2" },
  { type: "totp", singleton: true,
    icon: "M12 7v5l3 2m6-2a9 9 0 11-18 0 9 9 0 0118 0z" },
  { type: "hotp", singleton: true,
    icon: "M4 9h16M4 15h16M10 3L8 21M16 3l-2 18" },
  { type: "recovery-code", singleton: true,
    icon: "M9 12h6m-6 4h6m-7 4h8a2 2 0 002-2V8l-5-5H8a2 2 0 00-2 2v12a2 2 0 002 2zM13 3v5h5" },
];

export interface UserCredentialsProps {
  api: CredentialApi;
  realmId: string;
  userId: string;
  username: string;
  /** Bubble a toast up to the host page. */
  onNote: (n: { tone: "success" | "error"; title: string; message?: string }) => void;
}

/**
 * The "Device & passkeys" tab of a user's detail page: their complete authentication-factor surface —
 * every family always shown (enrolled or "Not set up") — with per-factor revoke. Self-contained: loads
 * its own data for the given user and confirms before revoking.
 *
 * Renders as an embedded tab fragment (the host UserDetailPage owns the <Page>/<PageHeader>), so it
 * derives its stack from <PageBody> rather than re-declaring page chrome.
 */
export function UserCredentials({ api, realmId, userId, username, onNote }: UserCredentialsProps) {
  const { t } = useT();
  const [creds, setCreds] = React.useState<CredentialSummary[] | null>(null);
  const [confirm, setConfirm] = React.useState<CredentialSummary | null>(null);
  const [busy, setBusy] = React.useState(false);

  const translatedKinds: FactorKind[] = KINDS.map((k) => ({
    ...k,
    title: t(`credentials.kind.${k.type}.title`),
    blurb: t(`credentials.kind.${k.type}.blurb`),
  }));

  const reload = React.useCallback(() => {
    setCreds(null);
    api.list(realmId, userId)
      .then(setCreds)
      .catch((e) => { setCreds([]); onNote({ tone: "error", title: t("credentials.load.error"), message: String(e.message ?? e) }); });
  }, [api, realmId, userId, onNote, t]);
  React.useEffect(reload, [reload]);

  const revoke = (cred: CredentialSummary) => {
    setBusy(true);
    api.revoke(realmId, userId, cred.type, cred.id)
      .then(() => {
        setCreds((prev) => (prev ?? []).filter((c) => !(c.type === cred.type && c.id === cred.id)));
        onNote({ tone: "success", title: t("credentials.revoked"), message: cred.label });
      })
      .catch((e) => onNote({ tone: "error", title: t("credentials.revoke.failed"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setConfirm(null); });
  };

  if (creds === null) {
    return <div className="hx-loadwrap"><Spinner size={24} label={t("credentials.loading")} /></div>;
  }

  const byType = (tp: string) => creds.filter((c) => c.type === tp);
  const known = new Set(KINDS.map((k) => k.type));
  const others = creds.filter((c) => !known.has(c.type));
  const enrolledKinds = KINDS.filter((k) => byType(k.type).length > 0).length + (others.length ? 1 : 0);

  return (
    <>
      <PageBody>
        {translatedKinds.map((k) => <FamilyCard key={k.type} kind={k} items={byType(k.type)} onRevoke={setConfirm} />)}
        {others.length > 0 && (
          <FamilyCard
            kind={{ type: "other", title: t("credentials.kind.other.title"), blurb: t("credentials.kind.other.blurb"), singleton: false, icon: "M5 12h.01M12 12h.01M19 12h.01" }}
            items={others} onRevoke={setConfirm} />
        )}
        <p className="hx-help">
          {t("credentials.summary", { enrolled: enrolledKinds, total: KINDS.length })}
        </p>
      </PageBody>

      <ConfirmDialog
        open={confirm !== null}
        title={t("credentials.confirm.title")}
        message={confirm ? t("credentials.confirm.msg", { label: confirm.label, name: username }) : ""}
        confirmLabel={busy ? t("credentials.revoking") : t("credentials.factor.revoke")}
        onConfirm={() => confirm && revoke(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </>
  );
}

function FamilyCard({ kind, items, onRevoke }: { kind: FactorKind; items: CredentialSummary[]; onRevoke: (c: CredentialSummary) => void }) {
  const { t } = useT();
  const enrolled = items.length > 0;
  const single = kind.singleton ? items[0] : undefined;
  return (
    <section className={enrolled ? "hx-card hx-section" : "hx-card hx-section hx-card--muted"}>
      <div className="hx-section__body">
        <div className="hx-pagebody">
          <div className="hx-conn">
            <IconTile d={kind.icon} />
            <div className="hx-conncard__body">
              <div className="hx-conn__name">{kind.title}</div>
              <div className="hx-help">{singleMeta(single, t) ?? kind.blurb}</div>
            </div>
            <div className="hx-badges">
              {enrolled
                ? (single
                    ? <><Badge tone="success">{t("credentials.factor.enabled")}</Badge>{single.revocable && <Button variant="ghost" onClick={() => onRevoke(single)}>{t("credentials.factor.revoke")}</Button>}</>
                    : <Badge tone="success">{t("credentials.factor.enrolled", { count: items.length })}</Badge>)
                : <span className="hx-help">{t("credentials.factor.notSetup")}</span>}
            </div>
          </div>

          {enrolled && !kind.singleton && (
            <div className="hx-tablescroll">
              <table className="hx-table">
                <tbody>
                  {items.map((c) => (
                    <tr key={c.type + c.id}>
                      <td>
                        <div className="hx-conn__name hx-nowrap">{instancePrimary(kind, c, t)}</div>
                        <div className="hx-help">{instanceMeta(c, t)}</div>
                      </td>
                      <td className="hx-cell-right">
                        {c.revocable && <Button variant="ghost" onClick={() => onRevoke(c)}>{t("credentials.factor.revoke")}</Button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function singleMeta(c: CredentialSummary | undefined, t: (key: string, params?: Record<string, string | number>) => string): string | null {
  if (!c) return null;
  if (c.createdAt) return t("credentials.enrolledOn", { date: formatDate(c.createdAt) });
  return c.detail || null;
}

function instancePrimary(kind: FactorKind, c: CredentialSummary, t: (key: string, params?: Record<string, string | number>) => string): string {
  if (kind.type === "passkey") return t("credentials.passkeyLabel", { id: c.id.slice(-8) });
  if (kind.type === "device") return c.detail || t("credentials.deviceLabel");
  return c.label;
}

function instanceMeta(c: CredentialSummary, t: (key: string, params?: Record<string, string | number>) => string): string {
  const parts: string[] = [];
  if (c.createdAt) parts.push(t("credentials.addedOn", { date: formatDate(c.createdAt) }));
  if (c.lastUsedAt) parts.push(t("credentials.lastUsed", { date: formatDate(c.lastUsedAt) }));
  return parts.length ? parts.join(" · ") : t("credentials.enrolmentUnknown");
}

function IconTile({ d }: { d: string }) {
  return (
    <span className="hx-icontile">
      <svg width={22} height={22} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={d} /></svg>
    </span>
  );
}

function formatDate(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "unknown" : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
