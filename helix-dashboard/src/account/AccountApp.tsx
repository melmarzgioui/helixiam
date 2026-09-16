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
    <div style={{ minHeight: "100vh", background: "var(--surface)", color: "var(--fg)", fontFamily: "var(--font)" }}>
      <header
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem",
          padding: "1rem 1.4rem", background: "var(--bg)", borderBottom: "1px solid var(--border)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: ".7rem" }}>
          <span style={{ fontWeight: 700, fontSize: "1.05rem" }}>{t("account.header.title")}</span>
          <Badge tone="accent">{activeRealm}</Badge>
        </div>
        {username && (
          <div style={{ display: "flex", alignItems: "center", gap: ".6rem", color: "var(--fg-muted)", fontSize: ".9rem" }}>
            <span>{username}</span>
            <a className="hx-btn hx-btn--ghost" href={`/realms/${encodeURIComponent(activeRealm)}/connect/logout`}
               style={{ textDecoration: "none", padding: ".4rem .85rem" }}>{t("account.header.signOut")}</a>
          </div>
        )}
      </header>

      <main style={{ maxWidth: 880, margin: "0 auto", padding: "1.6rem 1.4rem 4rem", width: "100%", boxSizing: "border-box" }}>
        <div style={{ marginBottom: "1.2rem" }}>
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
        <div style={{ position: "fixed", right: "1.2rem", bottom: "1.2rem", zIndex: 80 }}>
          <Toast tone={note.tone === "success" ? "success" : "error"} title={note.title} message={note.message}
                 onDismiss={() => setNote(null)} />
        </div>
      )}
    </div>
  );
}
