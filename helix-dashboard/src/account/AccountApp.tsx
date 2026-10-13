/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Badge } from "../components/Badge";
import { Tabs } from "../components/Tabs";
import { Toast } from "../components/Toast";
import { AccountApi, createAccountHttpClient } from "./api";
import { ProfileTab } from "./ProfileTab";
import { SecurityTab } from "./SecurityTab";
import { SessionsTab } from "./SessionsTab";
import { ConsentsTab } from "./ConsentsTab";
import { IdentitiesTab } from "./IdentitiesTab";
import { PrivacyTab } from "./PrivacyTab";
import { useT } from "../i18n/LocaleContext";

export type Note = { tone: "success" | "error"; title: string; message?: string };

/** Resolve the realm from the URL (/realms/:realm/account...) or VITE default; falls back to "master". */
function resolveRealm(): string {
  const m = window.location.pathname.match(/\/realms\/([^/]+)\//);
  if (m) return decodeURIComponent(m[1]);
  return (import.meta.env?.VITE_ACCOUNT_REALM as string) ?? "master";
}

export interface AccountAppProps {
  /** Inject for tests/stories; defaults to the HTTP client for the URL's realm. */
  api?: AccountApi;
  realm?: string;
}

/**
 * Helix IAM (6): the END-USER "my account" surface — a small, self-contained app distinct from the admin
 * console. The user signs in via the realm's OIDC; this manages only their own Profile, Security (password +
 * passkeys/MFA), Sessions and authorized Applications. Built from the same component kit + design tokens as
 * the admin console for a consistent, premium feel.
 */
export function AccountApp({ api, realm }: AccountAppProps) {
  const { t } = useT();
  const activeRealm = realm ?? resolveRealm();
  const client = React.useMemo(
    () => api ?? createAccountHttpClient(activeRealm, import.meta.env?.VITE_API_BASE ?? ""),
    [api, activeRealm],
  );

  const [tab, setTab] = React.useState("profile");
  const [note, setNote] = React.useState<Note | null>(null);
  const [username, setUsername] = React.useState<string>("");

  const tabs = [
    { id: "profile", label: t("account.tab.profile") },
    { id: "security", label: t("account.tab.security") },
    { id: "sessions", label: t("account.tab.sessions") },
    { id: "consents", label: t("account.tab.consents") },
    { id: "identities", label: t("account.tab.identities") },
    { id: "privacy", label: t("account.tab.privacy") },
  ];

  const onNote = React.useCallback((n: Note) => {
    setNote(n);
    window.setTimeout(() => setNote((cur) => (cur === n ? null : cur)), 5000);
  }, []);

  return (
    <div className="hx-acct">
      <header className="hx-acct__header">
        <div className="hx-acct__brand">
          <span className="hx-acct__brand-title">{t("account.header.title")}</span>
          <Badge tone="accent">{activeRealm}</Badge>
        </div>
        {username && (
          <div className="hx-acct__user">
            <span>{username}</span>
            <a className="hx-btn hx-btn--ghost hx-acct__signout" href={`/realms/${encodeURIComponent(activeRealm)}/connect/logout`}>
              {t("account.header.signOut")}
            </a>
          </div>
        )}
      </header>

      <main className="hx-acct__main">
        <div className="hx-acct__tabs">
          <Tabs tabs={tabs} value={tab} onChange={setTab} />
        </div>

        {tab === "profile" && <ProfileTab api={client} onNote={onNote} onUsername={setUsername} />}
        {tab === "security" && <SecurityTab api={client} onNote={onNote} />}
        {tab === "sessions" && <SessionsTab api={client} onNote={onNote} />}
        {tab === "consents" && <ConsentsTab api={client} onNote={onNote} />}
        {tab === "identities" && <IdentitiesTab api={client} onNote={onNote} />}
        {tab === "privacy" && <PrivacyTab api={client} onNote={onNote} />}
      </main>

      {note && (
        <div className="hx-acct__toast">
          <Toast tone={note.tone === "success" ? "success" : "error"} title={note.title} message={note.message}
                 onDismiss={() => setNote(null)} />
        </div>
      )}
    </div>
  );
}
