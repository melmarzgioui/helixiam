/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Spinner } from "../components/Spinner";
import { FormField, Input } from "../components/FormField";
import { AccountApi, AccountProfile } from "./api";
import { validateEmail } from "./validation";
import type { Note } from "./AccountApp";
import { useT } from "../i18n/LocaleContext";

/**
 * Helix IAM (6): the account Profile tab — the signed-in user views their own profile (username read-only) and
 * edits their email + simple attributes. Validates before save (block + inline error on a bad email).
 */
export function ProfileTab({ api, onNote, onUsername }: { api: AccountApi; onNote: (n: Note) => void; onUsername: (u: string) => void }) {
  const { t } = useT();
  const [profile, setProfile] = React.useState<AccountProfile | null>(null);
  const [email, setEmail] = React.useState("");
  const [emailError, setEmailError] = React.useState<string | undefined>();
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    api.getProfile()
      .then((p) => { setProfile(p); setEmail(p.email ?? ""); onUsername(p.username); })
      .catch((e) => onNote({ tone: "error", title: t("account.profile.error.loadFailed"), message: String(e.message ?? e) }));
  }, [api, onNote, onUsername]); // t omitted: error string is secondary to load logic

  if (!profile) {
    return <div style={{ padding: "3rem", display: "flex", justifyContent: "center" }}><Spinner size={24} label={t("account.profile.loading")} /></div>;
  }

  const save = () => {
    const err = validateEmail(email);
    setEmailError(err);
    if (err) return;
    setBusy(true);
    api.updateProfile({ email: email.trim() || null, attributes: profile.attributes })
      .then((p) => { setProfile(p); setEmail(p.email ?? ""); onNote({ tone: "success", title: t("account.profile.savedToast") }); })
      .catch((e) => onNote({ tone: "error", title: t("account.profile.saveFailedToast"), message: String(e.message ?? e) }))
      .finally(() => setBusy(false));
  };

  return (
    <div style={{ display: "grid", gap: "1rem" }}>
      <Card title={t("account.profile.card.title")} subtitle={t("account.profile.card.subtitle")}>
        <FormField label={t("account.profile.username")}>
          <Input value={profile.username} readOnly disabled aria-label={t("account.profile.username")} />
        </FormField>
        <FormField label={t("account.profile.email")} error={emailError} hint={t("account.profile.emailHint")}>
          <Input type="email" value={email} onChange={(e) => { setEmail(e.target.value); setEmailError(undefined); }}
                 placeholder={t("account.profile.emailPlaceholder")} aria-label={t("account.profile.email")} />
        </FormField>
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <Button onClick={save} disabled={busy}>{busy ? t("account.profile.saving") : t("account.profile.saveChanges")}</Button>
        </div>
      </Card>
    </div>
  );
}
