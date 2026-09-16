/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { FormField, Input } from "../components/FormField";
import { ConfirmDialog } from "../components/Modal";
import { AccountApi, AccountApiError, AccountCredential } from "./api";
import { validateChangePassword, isValid, ChangePasswordErrors } from "./validation";
import type { Note } from "./AccountApp";
import { useT } from "../i18n/LocaleContext";

/**
 * Helix IAM (6): the account Security tab — change your own password (verify current → set new) and manage
 * your own authentication factors (passkeys/MFA), reusing the admin factor-family layout. Enrolling a new
 * passkey hands off to the existing WebAuthn registration page.
 */
export function SecurityTab({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  return (
    <div style={{ display: "grid", gap: "1rem" }}>
      <ChangePasswordCard api={api} onNote={onNote} />
      <FactorsCard api={api} onNote={onNote} />
    </div>
  );
}

function ChangePasswordCard({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [fields, setFields] = React.useState({ currentPassword: "", newPassword: "", confirmPassword: "" });
  const [errors, setErrors] = React.useState<ChangePasswordErrors>({});
  const [busy, setBusy] = React.useState(false);
  const set = (k: keyof typeof fields) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setFields((f) => ({ ...f, [k]: e.target.value }));

  const submit = () => {
    const errs = validateChangePassword(fields);
    setErrors(errs);
    if (!isValid(errs)) return;
    setBusy(true);
    api.changePassword(fields.currentPassword, fields.newPassword)
      .then(() => {
        setFields({ currentPassword: "", newPassword: "", confirmPassword: "" });
        onNote({ tone: "success", title: t("account.security.passwordChangedToast") });
      })
      .catch((e) => {
        // The backend returns 400 when the current password is wrong — surface that on the right field.
        if (e instanceof AccountApiError && e.status === 400) {
          setErrors({ currentPassword: t("account.security.incorrectPasswordError") });
        } else {
          onNote({ tone: "error", title: t("account.security.changePasswordError"), message: String(e.message ?? e) });
        }
      })
      .finally(() => setBusy(false));
  };

  return (
    <Card title={t("account.security.password.title")} subtitle={t("account.security.password.subtitle")}>
      <FormField label={t("account.security.currentPassword")} error={errors.currentPassword} required>
        <Input type="password" autoComplete="current-password" value={fields.currentPassword} onChange={set("currentPassword")} aria-label={t("account.security.currentPassword")} />
      </FormField>
      <FormField label={t("account.security.newPassword")} error={errors.newPassword} hint={t("account.security.newPasswordHint")} required>
        <Input type="password" autoComplete="new-password" value={fields.newPassword} onChange={set("newPassword")} aria-label={t("account.security.newPassword")} />
      </FormField>
      <FormField label={t("account.security.confirmPassword")} error={errors.confirmPassword} required>
        <Input type="password" autoComplete="new-password" value={fields.confirmPassword} onChange={set("confirmPassword")} aria-label={t("account.security.confirmPassword")} />
      </FormField>
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <Button onClick={submit} disabled={busy}>{busy ? t("account.security.changing") : t("account.security.changePassword")}</Button>
      </div>
    </Card>
  );
}

function FactorsCard({ api, onNote }: { api: AccountApi; onNote: (n: Note) => void }) {
  const { t } = useT();
  const [creds, setCreds] = React.useState<AccountCredential[] | null>(null);
  const [confirm, setConfirm] = React.useState<AccountCredential | null>(null);
  const [busy, setBusy] = React.useState(false);

  /** Factor families shown (phishing-resistant first), mirroring the admin Device & passkeys screen. */
  const kinds: { type: string; title: string; blurb: string; canEnroll?: "passkey" }[] = [
    { type: "passkey", title: t("account.security.factor.passkeys.title"), blurb: t("account.security.factor.passkeys.blurb"), canEnroll: "passkey" },
    { type: "device", title: t("account.security.factor.devices.title"), blurb: t("account.security.factor.devices.blurb") },
    { type: "totp", title: t("account.security.factor.totp.title"), blurb: t("account.security.factor.totp.blurb") },
    { type: "hotp", title: t("account.security.factor.hotp.title"), blurb: t("account.security.factor.hotp.blurb") },
    { type: "recovery-code", title: t("account.security.factor.recoveryCodes.title"), blurb: t("account.security.factor.recoveryCodes.blurb") },
  ];

  const reload = React.useCallback(() => {
    setCreds(null);
    api.listCredentials()
      .then(setCreds)
      .catch((e) => { setCreds([]); onNote({ tone: "error", title: t("account.security.loadFactorsError"), message: String(e.message ?? e) }); });
  }, [api, onNote, t]);
  React.useEffect(reload, [reload]);

  const revoke = (c: AccountCredential) => {
    setBusy(true);
    api.revokeCredential(c.type, c.id)
      .then(() => {
        setCreds((prev) => (prev ?? []).filter((x) => !(x.type === c.type && x.id === c.id)));
        onNote({ tone: "success", title: t("account.security.factor.removedToast"), message: c.label });
      })
      .catch((e) => onNote({ tone: "error", title: t("account.security.factor.removeError"), message: String(e.message ?? e) }))
      .finally(() => { setBusy(false); setConfirm(null); });
  };

  if (creds === null) {
    return <Card title={t("account.security.mfa.title")}><div style={{ padding: "1.5rem", display: "flex", justifyContent: "center" }}><Spinner size={22} label={t("account.security.loadingFactors")} /></div></Card>;
  }

  const byType = (type: string) => creds.filter((c) => c.type === type);

  return (
    <Card title={t("account.security.mfa.title")} subtitle={t("account.security.mfa.subtitle")}>
      <div style={{ display: "grid", gap: ".75rem" }}>
        {kinds.map((k) => {
          const items = byType(k.type);
          const enrolled = items.length > 0;
          return (
            <div key={k.type} className="hx-card" style={{ padding: ".9rem 1.1rem", opacity: enrolled ? 1 : 0.78 }}>
              <div style={{ display: "flex", alignItems: "center", gap: ".85rem" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600 }}>{k.title}</div>
                  <div style={{ color: "var(--fg-muted)", fontSize: ".8rem" }}>{k.blurb}</div>
                </div>
                <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: ".55rem" }}>
                  {enrolled ? <Badge tone="success">{t("account.security.factor.activeCount", { count: items.length })}</Badge>
                    : <span style={{ color: "var(--fg-faint)", fontSize: ".82rem", fontWeight: 500 }}>{t("account.security.factor.notSetUp")}</span>}
                  {k.canEnroll === "passkey" && (
                    <a className="hx-btn hx-btn--ghost" href="/webauthn/register" style={{ textDecoration: "none", padding: ".4rem .85rem" }}>{t("account.security.factor.add")}</a>
                  )}
                </div>
              </div>
              {enrolled && (
                <div style={{ marginTop: ".7rem", borderTop: "1px solid var(--border)", display: "grid" }}>
                  {items.map((c, i) => (
                    <div key={c.type + c.id} style={{ display: "flex", alignItems: "center", gap: "1rem", padding: ".6rem .1rem", borderTop: i === 0 ? "none" : "1px solid var(--border)" }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontWeight: 500, fontSize: ".9rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.label}</div>
                        <div style={{ color: "var(--fg-faint)", fontSize: ".76rem" }}>{c.detail || meta(c, t)}</div>
                      </div>
                      {c.revocable && <Button variant="ghost" onClick={() => setConfirm(c)} style={{ padding: ".4rem .85rem", flexShrink: 0 }}>{t("account.security.factor.remove")}</Button>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <ConfirmDialog
        open={confirm !== null}
        title={t("account.security.factor.removeDialog.title")}
        message={confirm ? t("account.security.factor.removeDialog.message", { label: confirm.label }) : ""}
        confirmLabel={busy ? t("account.security.factor.removing") : t("account.security.factor.remove")}
        onConfirm={() => confirm && revoke(confirm)}
        onCancel={() => setConfirm(null)}
      />
    </Card>
  );
}

function meta(c: AccountCredential, t: (key: string, params?: Record<string, string | number>) => string): string {
  const parts: string[] = [];
  if (c.createdAt) parts.push(t("account.security.factor.added", { date: new Date(c.createdAt).toLocaleDateString() }));
  if (c.lastUsedAt) parts.push(t("account.security.factor.lastUsed", { date: new Date(c.lastUsedAt).toLocaleDateString() }));
  return parts.join(" · ");
}
