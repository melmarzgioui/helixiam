/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Spinner } from "../components/Spinner";
import { Toast } from "../components/Toast";
import { Badge } from "../components/Badge";
import { Tabs } from "../components/Tabs";
import { Modal, ConfirmDialog } from "../components/Modal";
import { UserApi, UserSummary, UserWrite, REQUIRED_ACTION_OPTIONS, parseRequiredActions } from "../api/users";
import { RoleApi } from "../api/roles";
import { CredentialApi } from "../api/credentials";
import { SessionApi, IdentitySession } from "../api/sessions";
import { Avatar, StatusBadge, UserForm, ResetForm, RolesManager, Note } from "./UsersPage";
import { UserCredentials } from "./userCredentials";
import { useT } from "../i18n/LocaleContext";

export interface UserDetailPageProps {
  api: UserApi;
  roleApi: RoleApi;
  credentialApi: CredentialApi;
  sessionApi: SessionApi;
  realmId: string;
  userId: string;
  onBack: () => void;
}

/**
 * user detail: everything about one realm user, in tabs — profile (Details), realm role
 * mappings, their authentication factors (Device & passkeys) and active SSO sessions. Reached by opening
 * a row on the Users screen; the per-user credential/session views live here rather than as standalone pages.
 */
export function UserDetailPage({ api, roleApi, credentialApi, sessionApi, realmId, userId, onBack }: UserDetailPageProps) {
  const { t } = useT();

  const TABS = [
    { id: "details", label: t("userDetail.tab.details") },
    { id: "roles", label: t("userDetail.tab.roles") },
    { id: "credentials", label: t("userDetail.tab.credentials") },
    { id: "sessions", label: t("userDetail.tab.sessions") },
  ];

  const [user, setUser] = React.useState<UserSummary | null>(null);
  const [missing, setMissing] = React.useState(false);
  const [tab, setTab] = React.useState("details");
  const [resetOpen, setResetOpen] = React.useState(false);
  const [toDelete, setToDelete] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    api.get(realmId, userId)
      .then((u) => { setUser(u); setMissing(false); })
      .catch(() => setMissing(true));
  }, [api, realmId, userId]);
  React.useEffect(reload, [reload]);

  const save = async (write: UserWrite) => {
    try {
      const saved = await api.update(realmId, userId, write);
      setUser(saved);
      setNote({ tone: "success", title: t("users.updated"), message: t("users.updated.msg", { name: saved.username }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.save.error"), message: String((e as Error).message ?? e) });
    }
  };

  const submitReset = async (pw: string) => {
    setResetOpen(false);
    try {
      await api.resetPassword(realmId, userId, pw);
      setNote({ tone: "success", title: t("users.password.reset"), message: t("users.password.reset.msg", { name: user?.username ?? "" }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.password.reset.error"), message: String((e as Error).message ?? e) });
    }
  };

  const impersonate = async () => {
    try {
      const res = await api.impersonate(realmId, userId);
      setNote({ tone: "success", title: t("userDetail.impersonating", { name: res.impersonating }), message: t("userDetail.impersonating.msg") });
      window.open(res.redirectUrl, "_blank", "noopener");
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("userDetail.impersonate.error"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    setToDelete(false);
    try {
      await api.remove(realmId, userId);
      onBack();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("users.remove.error"), message: String((e as Error).message ?? e) });
    }
  };

  if (missing) {
    return (
      <Page>
        <button type="button" onClick={onBack} className="hx-backlink">{t("userDetail.back")}</button>
        <p className="hx-muted">{t("userDetail.notFound", { realm: realmId })}</p>
      </Page>
    );
  }
  if (user === null) {
    return <div className="hx-loadwrap"><Spinner size={28} label={t("userDetail.loading")} /></div>;
  }

  return (
    <Page>
      <button type="button" onClick={onBack} className="hx-backlink">{t("userDetail.back")}</button>

      <PageHeader
        title={<span className="hx-namecell"><Avatar name={user.username} size={46} />{user.username}</span>}
        description={user.email ?? user.userId}
        actions={
          <span className="hx-badges">
            <StatusBadge enabled={user.enabled} locked={user.locked} />
            {user.mfaEnabled ? <Badge tone="success">{t("userDetail.mfa.on")}</Badge> : <Badge tone="warning">{t("userDetail.mfa.off")}</Badge>}
          </span>
        }
      />

      <PageBody>
        <Tabs tabs={TABS} value={tab} onChange={setTab} />

        {tab === "details" && (
          <>
            <Section title={t("userDetail.section.profile")}>
              <UserForm key={user.userId} initial={user} onSubmit={save} onCancel={reload} />
              <div className="hx-formactions">
                <span className="hx-badges">
                  <Button variant="ghost" onClick={() => setResetOpen(true)}>{t("userDetail.resetPassword")}</Button>
                  <Button variant="ghost" onClick={impersonate}>{t("userDetail.impersonate")}</Button>
                  <Button variant="ghost" className="hx-btn--danger" onClick={() => setToDelete(true)}>{t("userDetail.remove")}</Button>
                </span>
              </div>
            </Section>
            <RequiredActionsManager api={api} realmId={realmId} userId={user.userId} onNote={setNote} />
          </>
        )}

        {tab === "roles" && (
          <Section title={t("userDetail.section.roles")}>
            <RolesManager roleApi={roleApi} realmId={realmId} user={user} onNote={setNote} />
          </Section>
        )}

        {tab === "credentials" && (
          <UserCredentials api={credentialApi} realmId={realmId} userId={user.userId} username={user.username} onNote={setNote} />
        )}

        {tab === "sessions" && (
          <UserSessions sessionApi={sessionApi} realmId={realmId} username={user.username} userId={user.userId} onNote={setNote} />
        )}
      </PageBody>

      <Modal open={resetOpen} title={t("users.modal.resetPassword")} onClose={() => setResetOpen(false)} width={460}>
        <ResetForm username={user.username} onSubmit={submitReset} onCancel={() => setResetOpen(false)} />
      </Modal>

      <ConfirmDialog
        open={toDelete}
        title={t("users.confirm.remove.title")}
        message={t("users.confirm.remove.msg", { name: user.username, realm: realmId })}
        onConfirm={confirmDelete}
        onCancel={() => setToDelete(false)}
      />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

/** This user's active SSO sessions (filtered from the realm rollup), each cascade-revocable. */
function UserSessions({ sessionApi, realmId, username, userId, onNote }: {
  sessionApi: SessionApi; realmId: string; username: string; userId: string; onNote: (n: Note) => void;
}) {
  const { t } = useT();
  const [sessions, setSessions] = React.useState<IdentitySession[] | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);

  const reload = React.useCallback(() => {
    setSessions(null);
    sessionApi.list(realmId)
      .then((all) => setSessions(all.filter((s) => s.principalName === username || s.principalName === userId)))
      .catch((e) => { setSessions([]); onNote({ tone: "error", title: t("userDetail.sessions.load.error"), message: String(e.message ?? e) }); });
  }, [sessionApi, realmId, username, userId, onNote, t]);
  React.useEffect(reload, [reload]);

  const revoke = (s: IdentitySession) => {
    setBusy(s.id);
    sessionApi.revoke(realmId, s.id)
      .then(() => { setSessions((prev) => (prev ?? []).filter((x) => x.id !== s.id)); onNote({ tone: "info", title: t("userDetail.sessions.revoked") }); })
      .catch((e) => onNote({ tone: "error", title: t("userDetail.sessions.revoke.error"), message: String(e.message ?? e) }))
      .finally(() => setBusy(null));
  };

  return (
    <Section title={t("userDetail.section.sessions")}>
      {sessions === null ? (
        <div className="hx-loadwrap"><Spinner size={24} label={t("userDetail.sessions.loading")} /></div>
      ) : sessions.length === 0 ? (
        <p className="hx-muted">{t("userDetail.sessions.empty")}</p>
      ) : (
        <div className="hx-cards">
          {sessions.map((s) => (
            <div key={s.id} className="hx-rowcard">
              <div className="hx-rowcard__head">
                <div className="hx-rowcard__grow">
                  <div className="hx-rowcard__title">
                    {s.clients.length === 1
                      ? t("userDetail.sessions.appCount", { count: s.clients.length })
                      : t("userDetail.sessions.appsCount", { count: s.clients.length })}
                  </div>
                  <div className="hx-badges">
                    {s.clients.length ? s.clients.map((c) => <Badge key={c.clientId} tone="neutral">{c.clientId}</Badge>) : "—"}
                  </div>
                  <div className="hx-rowcard__sub">
                    {s.issuedAt ? t("userDetail.sessions.started", { when: formatWhen(s.issuedAt) }) : t("userDetail.sessions.startUnknown")}{s.expiresAt ? t("userDetail.sessions.expires", { when: formatWhen(s.expiresAt) }) : ""}
                  </div>
                </div>
                <div className="hx-rowcard__actions">
                  <Button variant="ghost" className="hx-btn--danger" disabled={busy === s.id} onClick={() => revoke(s)}>
                    {busy === s.id ? t("userDetail.sessions.revoking") : t("userDetail.sessions.revoke")}
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Section>
  );
}

/**
 * B1: assign the actions a user must complete at their next login (e.g. UPDATE_PASSWORD). The auth server
 * holds the user on a partial session after password verification and forces each action before issuing a
 * full session / running MFA. Editing here is a full replace of the user's pending list.
 */
function RequiredActionsManager({ api, realmId, userId, onNote }: {
  api: UserApi; realmId: string; userId: string; onNote: (n: Note) => void;
}) {
  const { t } = useT();
  const [selected, setSelected] = React.useState<string[] | null>(null);
  const [saving, setSaving] = React.useState(false);

  const reload = React.useCallback(() => {
    setSelected(null);
    api.getRequiredActions(realmId, userId)
      .then((csv) => setSelected(parseRequiredActions(csv)))
      .catch((e) => { setSelected([]); onNote({ tone: "error", title: t("userDetail.requiredActions.load.error"), message: String(e.message ?? e) }); });
  }, [api, realmId, userId, onNote, t]);
  React.useEffect(reload, [reload]);

  const toggle = (key: string) =>
    setSelected((prev) => (prev ?? []).includes(key) ? (prev ?? []).filter((k) => k !== key) : [...(prev ?? []), key]);

  const save = async () => {
    setSaving(true);
    try {
      await api.setRequiredActions(realmId, userId, (selected ?? []).join(","));
      onNote({ tone: "success", title: t("userDetail.requiredActions.saved"), message: (selected ?? []).length ? t("userDetail.requiredActions.saved.pending") : t("userDetail.requiredActions.saved.cleared") });
    } catch (e: unknown) {
      onNote({ tone: "error", title: t("userDetail.requiredActions.save.error"), message: String((e as Error).message ?? e) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Section
      title={t("userDetail.requiredActions.title")}
      description={t("userDetail.requiredActions.description")}
    >
      {selected === null ? (
        <div className="hx-loadwrap"><Spinner size={22} label={t("common.loading")} /></div>
      ) : (
        <>
          <div className="hx-checklist">
            {REQUIRED_ACTION_OPTIONS.map((opt) => (
              <label key={opt.key} className="hx-checklist__item">
                <input type="checkbox" checked={selected.includes(opt.key)} onChange={() => toggle(opt.key)} />
                <span>{opt.label}</span>
                <code className="hx-faint hx-mono">{opt.key}</code>
              </label>
            ))}
          </div>
          <div className="hx-formactions">
            <span className="hx-badges">
              <Button onClick={save} disabled={saving}>{saving ? t("userDetail.requiredActions.saving") : t("userDetail.requiredActions.save")}</Button>
              <Button variant="ghost" onClick={reload} disabled={saving}>{t("userDetail.requiredActions.reset")}</Button>
            </span>
          </div>
        </>
      )}
    </Section>
  );
}

function formatWhen(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "unknown";
  return new Date(t).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
