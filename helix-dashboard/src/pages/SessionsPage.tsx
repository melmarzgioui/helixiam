import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { Input } from "../components/FormField";
import { Drawer } from "../components/Drawer";
import { DetailList, Detail } from "../components/DetailList";
import { relativeTime, absoluteTime } from "../api/datetime";
import { SessionApi, IdentitySession, IdentityType } from "../api/sessions";
import { decodeJwtSid, decodeJwtSub } from "../api/jwt";
import { ID_TOKEN_KEY } from "../api/session";
import { useT } from "../i18n/LocaleContext";

export interface SessionsPageProps {
  api: SessionApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

type BadgeTone = "neutral" | "success" | "warning" | "danger" | "accent";

/** Sessions v2: unified "Active identities" — user / agent / service-account rows, filtered server-side,
 *  with a right-side Drawer for detail and current-session highlighting via the id_token sid. */
export function SessionsPage({ api, realmId }: SessionsPageProps) {
  const { t, locale } = useT();
  const [rows, setRows] = React.useState<IdentitySession[] | null>(null);
  const [query, setQuery] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState("");
  const [selected, setSelected] = React.useState<IdentitySession | null>(null);
  const [toRevoke, setToRevoke] = React.useState<IdentitySession | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);

  const TYPE_META: Record<IdentityType, { label: string; tone: BadgeTone }> = React.useMemo(() => ({
    USER: { label: t("sessions.type.user"), tone: "neutral" },
    AGENT: { label: t("sessions.type.agent"), tone: "accent" },
    SERVICE_ACCOUNT: { label: t("sessions.type.serviceAccount"), tone: "warning" },
    WORKLOAD: { label: t("sessions.type.workload"), tone: "success" },
  }), [t]);

  const TYPE_FILTERS: { value: string; label: string }[] = React.useMemo(() => [
    { value: "", label: t("sessions.filter.all") },
    { value: "user", label: t("sessions.filter.users") },
    { value: "agent", label: t("sessions.filter.agents") },
    { value: "service_account", label: t("sessions.filter.serviceAccounts") },
    { value: "workload", label: t("sessions.filter.workloads") },
  ], [t]);

  const grantLabel = React.useCallback((g: string) => {
    const labels: Record<string, string> = {
      authorization_code: t("sessions.grant.authorizationCode"),
      client_credentials: t("sessions.grant.clientCredentials"),
      refresh_token: t("sessions.grant.refreshToken"),
      "urn:ietf:params:oauth:grant-type:device_code": t("sessions.grant.deviceCode"),
    };
    return labels[g] ?? g.replace(/_/g, " ");
  }, [t]);

  // Flag the admin's own row. Helix id_tokens may omit `sid` (the SSO rollup then keys by the user id), so
  // match on the precise `sid` when present, otherwise on the user `sub` vs the row's principalName.
  const { currentSid, currentSub } = React.useMemo(() => {
    const idt = sessionStorage.getItem(ID_TOKEN_KEY);
    return { currentSid: decodeJwtSid(idt), currentSub: decodeJwtSub(idt) };
  }, []);
  const isCurrent = React.useCallback(
    (s: IdentitySession) => (!!currentSid && s.id === currentSid) || (!!currentSub && s.principalName === currentSub),
    [currentSid, currentSub],
  );

  const load = React.useCallback((q: string, type: string) => {
    setRows(null);
    api.list(realmId, { q, type }).then(setRows).catch((e) => {
      setRows([]);
      setNote({ tone: "error", title: t("sessions.error.load"), message: String(e.message ?? e) });
    });
  }, [api, realmId, t]);

  // Debounced server-side filter: refetch when the search text or type filter changes.
  React.useEffect(() => {
    const timer = setTimeout(() => load(query, typeFilter), 250);
    return () => clearTimeout(timer);
  }, [load, query, typeFilter]);

  const confirmRevoke = async () => {
    if (!toRevoke) return;
    const target = toRevoke;
    const wasCurrent = isCurrent(target);
    setToRevoke(null);
    setSelected(null);
    try {
      await api.revoke(realmId, target.id);
      if (wasCurrent) {
        // Revoked our own session — the next admin call will bounce to login; nudge immediately.
        window.location.assign("/realms/master/login");
        return;
      }
      setNote({ tone: "info", title: t("sessions.revoked.title"), message: t("sessions.revoked.msg", { name: target.displayName }) });
      load(query, typeFilter);
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("sessions.error.revoke"), message: String((e as Error).message ?? e) });
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("sessions.title")}
        description={<>{t("sessions.description.pre")}<strong>{realmId}</strong>{t("sessions.description.post")}</>}
        actions={<Button variant="ghost" onClick={() => load(query, typeFilter)} disabled={rows === null}>{t("sessions.action.refresh")}</Button>}
      />

      <PageBody>
        <div className="hx-filterbar">
          <Input
            placeholder={t("sessions.search.placeholder")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label={t("sessions.search.label")}
          />
          <select className="hx-input" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} aria-label={t("sessions.typeFilter.label")}>
            {TYPE_FILTERS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
        </div>

        {rows === null ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("sessions.loading")} /></div>
        ) : rows.length === 0 ? (
          <EmptyState
            title={query || typeFilter ? t("sessions.empty.title.filtered") : t("sessions.empty.title.all")}
            message={query || typeFilter
              ? t("sessions.empty.msg.filtered")
              : t("sessions.empty.msg.all")}
          />
        ) : (
          <div className="hx-card">
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr>
                    <th>{t("sessions.col.type")}</th><th>{t("sessions.col.identity")}</th><th>{t("sessions.col.apps")}</th><th>{t("sessions.col.signedIn")}</th><th>{t("sessions.col.expires")}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((s) => (
                    <tr key={s.id} className="hx-row-clickable" onClick={() => setSelected(s)}>
                      <td><Badge tone={TYPE_META[s.identityType].tone}>{TYPE_META[s.identityType].label}</Badge></td>
                      <td>
                        <strong>{s.displayName}</strong>
                        {isCurrent(s) && <> <Badge tone="success">{t("sessions.badge.current")}</Badge></>}
                      </td>
                      <td>
                        {(() => {
                          const apps = [...new Set(s.clients.map((c) => c.clientId))];
                          return (
                            <span className="hx-badges">
                              {apps.slice(0, 3).map((id) => <Badge key={id} tone="accent">{id}</Badge>)}
                              {apps.length > 3 && <Badge tone="neutral">+{apps.length - 3}</Badge>}
                            </span>
                          );
                        })()}
                      </td>
                      <td className="hx-muted" title={absoluteTime(s.issuedAt, locale)}>{relativeTime(s.issuedAt)}</td>
                      <td className="hx-muted" title={absoluteTime(s.expiresAt, locale)}>{relativeTime(s.expiresAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </PageBody>

      <Drawer
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={t("sessions.drawer.title")}
        footer={selected && (
          <Button variant="danger" onClick={() => setToRevoke(selected)}>
            {selected.revokeMode === "SLO" ? t("sessions.drawer.revokeMode.slo") : t("sessions.drawer.revokeMode.token")}
          </Button>
        )}
      >
        {selected && (
          <>
            <DetailList>
              <Detail label={t("sessions.drawer.field.type")} center>
                <Badge tone={TYPE_META[selected.identityType].tone}>{TYPE_META[selected.identityType].label}</Badge>
              </Detail>
              <Detail label={t("sessions.drawer.field.identity")} mono={selected.principalName}>
                {selected.displayName}
                {isCurrent(selected) && <span className="hx-current-dot"> {t("sessions.drawer.field.currentSession")}</span>}
              </Detail>
              <Detail label={t("sessions.drawer.field.realm")}>{selected.realm}</Detail>
              <Detail label={t("sessions.drawer.field.signedIn")} sub={absoluteTime(selected.issuedAt, locale)}>
                {relativeTime(selected.issuedAt)}
              </Detail>
              <Detail label={t("sessions.drawer.field.expires")} sub={absoluteTime(selected.expiresAt, locale)}>
                {relativeTime(selected.expiresAt)}
              </Detail>
              <Detail label={t("sessions.drawer.field.apps")}>
                <div className="hx-dl__stack">
                  {selected.clients.map((c, i) => (
                    <div key={`${c.clientId}-${i}`}>
                      <strong>{c.clientId}</strong> <Badge tone="neutral">{grantLabel(c.grantType)}</Badge>
                      {c.scopes.length > 0 && <span className="hx-badges"> {c.scopes.map((sc) => <Badge key={sc} tone="accent">{sc}</Badge>)}</span>}
                    </div>
                  ))}
                </div>
              </Detail>
              <Detail label={t("sessions.drawer.field.sessionId")} mono={selected.id} />
            </DetailList>
          </>
        )}
      </Drawer>

      <ConfirmDialog
        open={toRevoke !== null}
        title={toRevoke && isCurrent(toRevoke) ? t("sessions.confirm.revokeSelf.title") : (toRevoke?.revokeMode === "SLO" ? t("sessions.confirm.revokeAll.title") : t("sessions.confirm.revokeToken.title"))}
        message={toRevoke && isCurrent(toRevoke)
          ? t("sessions.confirm.revokeSelf.msg")
          : toRevoke?.revokeMode === "SLO"
            ? t("sessions.confirm.revokeAll.msg", { name: toRevoke?.displayName ?? "" })
            : t("sessions.confirm.revokeToken.msg", { name: toRevoke?.displayName ?? "" })}
        onConfirm={confirmRevoke}
        onCancel={() => setToRevoke(null)}
      />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}
