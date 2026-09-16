import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { Alert } from "../components/Alert";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { Divider } from "../components/Divider";
import { Tabs } from "../components/Tabs";
import { FormField, Input, Textarea } from "../components/FormField";
import { Select } from "../components/Select";
import { Checkbox } from "../components/Choice";
import { RowMenu } from "../components/RowMenu";
import { ClientApi, Client, ClientWrite, clientLabel } from "../api/clients";
import { ClaimApi, Claim, ScopeApi, ClientScope } from "../api/scopes";
import { FlowApi, FlowSummary } from "../api/flows";
import { MapperApi, ProtocolMapper, MapperWrite } from "../api/mappers";
import { ClientRoleApi, ClientRole, ServiceAccountRole } from "../api/clientRoles";
import { RoleApi, Role } from "../api/roles";
import { AuthzApi } from "../api/authz";
import { AuthorizationTab } from "./AuthorizationTab";
import { GRANT_TYPES, SCOPES } from "./clientConstants";
import { WorkloadIdentityPage } from "./WorkloadIdentityPage";
import { WorkloadIdentityApi } from "../api/workloadIdentity";
import { AgentsPage } from "./AgentsPage";
import { AgentApi } from "../api/agents";
import { useT } from "../i18n/LocaleContext";

export interface ClientDetailPageProps {
  api: ClientApi;
  claimApi: ClaimApi;
  flowApi: FlowApi;
  scopeApi: ScopeApi;
  mapperApi: MapperApi;
  clientRoleApi: ClientRoleApi;
  roleApi: RoleApi;
  authzApi: AuthzApi;
  realmId: string;
  clientId: string; // the service-provider id (route detail segment)
  onBack: () => void;
  onDeleted: () => void;
  /** Hide the "← Clients" backlink when this editor is embedded under an Application's OIDC tab. */
  embedded?: boolean;
  /** When provided (Application OIDC tab), surface Workload identity + Agents as OIDC-client sub-tabs — both are OIDC/OAuth-only machine-identity features that ride this client's service account. */
  workloadIdentityApi?: WorkloadIdentityApi;
  agentsApi?: AgentApi;
}

interface Note { tone: ToastTone; title: string; message?: string; }
type TabId = "settings" | "credentials" | "login" | "scopes" | "mappers" | "keys" | "roles" | "serviceaccount" | "workloadidentity" | "agents" | "authorization" | "advanced";

/** full-page client editor — tabbed: Settings · Credentials · Client scopes · Advanced. */
export function ClientDetailPage({ api, claimApi, flowApi, scopeApi, mapperApi, clientRoleApi, roleApi, authzApi, realmId, clientId, onBack, onDeleted, embedded, workloadIdentityApi, agentsApi }: ClientDetailPageProps) {
  const { t } = useT();
  const [loaded, setLoaded] = React.useState<Client | null>(null);
  const [catalogue, setCatalogue] = React.useState<Claim[]>([]);
  const [flows, setFlows] = React.useState<FlowSummary[]>([]);
  const [scopeCatalog, setScopeCatalog] = React.useState<ClientScope[]>([]);
  const [err, setErr] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);
  const [newSecret, setNewSecret] = React.useState<string | null>(null);
  const [revealed, setRevealed] = React.useState<string | null>(null);
  const [confirmDel, setConfirmDel] = React.useState(false);
  const [tab, setTab] = React.useState<TabId>("settings");

  // editable state
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [grants, setGrants] = React.useState<string[]>([]);
  const [uris, setUris] = React.useState<string[]>([""]);
  const [logoutUris, setLogoutUris] = React.useState<string[]>([""]);
  const [webOrigins, setWebOrigins] = React.useState<string[]>([""]);
  const [scopes, setScopes] = React.useState<string[]>([]);
  const [subjectClaim, setSubjectClaim] = React.useState("");
  const [authFlowAlias, setAuthFlowAlias] = React.useState("");
  const [publicClient, setPublicClient] = React.useState(false);
  const [consentRequired, setConsentRequired] = React.useState(false);
  const [displayOnConsent, setDisplayOnConsent] = React.useState(true);
  const [loginTheme, setLoginTheme] = React.useState("");
  const [rootUrl, setRootUrl] = React.useState("");
  const [homeUrl, setHomeUrl] = React.useState("");
  const [adminUrl, setAdminUrl] = React.useState("");
  const [alwaysDisplay, setAlwaysDisplay] = React.useState(false);
  const [accessLifespan, setAccessLifespan] = React.useState("");
  const [refreshLifespan, setRefreshLifespan] = React.useState("");
  const [idTokenAlg, setIdTokenAlg] = React.useState("");
  const [reuseRefresh, setReuseRefresh] = React.useState(false);
  const [tokenAuthMethod, setTokenAuthMethod] = React.useState("");
  const [jwksUrl, setJwksUrl] = React.useState("");
  const [backchannelLogoutUri, setBackchannelLogoutUri] = React.useState("");
  const [frontchannelLogoutUri, setFrontchannelLogoutUri] = React.useState("");
  // B11 FAPI: mTLS cert-bound tokens / required signed Request Object (JAR) / JARM response mode.
  const [certBoundTokens, setCertBoundTokens] = React.useState(false);
  const [requireSignedRequest, setRequireSignedRequest] = React.useState(false);
  const [jarmResponseMode, setJarmResponseMode] = React.useState("");
  const [attempted, setAttempted] = React.useState(false);

  const hydrate = React.useCallback((c: Client) => {
    setLoaded(c);
    setName(c.name ?? "");
    setDescription(c.description ?? "");
    setGrants(c.grantTypes);
    setUris(c.redirectUris.length ? c.redirectUris : [""]);
    setLogoutUris(c.postLogoutRedirectUris.length ? c.postLogoutRedirectUris : [""]);
    setWebOrigins(c.webOrigins.length ? c.webOrigins : [""]);
    setScopes(c.scopes);
    setSubjectClaim(c.subjectClaim ?? "");
    setAuthFlowAlias(c.authFlowAlias ?? "");
    setPublicClient(c.publicClient);
    setConsentRequired(c.consentRequired);
    setDisplayOnConsent(c.displayOnConsentScreen);
    setLoginTheme(c.loginTheme ?? "");
    setRootUrl(c.rootUrl ?? "");
    setHomeUrl(c.homeUrl ?? "");
    setAdminUrl(c.adminUrl ?? "");
    setAlwaysDisplay(c.alwaysDisplayInConsole);
    setAccessLifespan(c.accessTokenLifespan != null ? String(c.accessTokenLifespan) : "");
    setRefreshLifespan(c.refreshTokenLifespan != null ? String(c.refreshTokenLifespan) : "");
    setIdTokenAlg(c.idTokenSignatureAlg ?? "");
    setReuseRefresh(c.reuseRefreshTokens);
    setTokenAuthMethod(c.tokenEndpointAuthMethod ?? "");
    setJwksUrl(c.jwksUrl ?? "");
    setBackchannelLogoutUri(c.backchannelLogoutUri ?? "");
    setFrontchannelLogoutUri(c.frontchannelLogoutUri ?? "");
    setCertBoundTokens(c.x509CertificateBoundAccessTokens ?? false);
    setRequireSignedRequest(c.requireSignedRequestObject ?? false);
    setJarmResponseMode(c.jarmResponseMode ?? "");
    setRevealed(null);
  }, []);

  const reload = React.useCallback(() => {
    setLoaded(null); setErr(null);
    api.list(realmId).then((rows) => {
      const c = rows.find((r) => r.id === clientId || r.clientId === clientId);
      if (c) hydrate(c); else setErr(t("clientDetail.notFound"));
    }).catch((e) => setErr(String(e.message ?? e)));
  }, [api, realmId, clientId, hydrate, t]);

  React.useEffect(reload, [reload]);
  React.useEffect(() => { claimApi.list(realmId).then(setCatalogue).catch(() => undefined); }, [claimApi, realmId]);
  React.useEffect(() => { flowApi.list(realmId).then(setFlows).catch(() => undefined); }, [flowApi, realmId]);
  React.useEffect(() => { scopeApi.list(realmId).then(setScopeCatalog).catch(() => undefined); }, [scopeApi, realmId]);

  const browserFlow = grants.includes("authorization_code");
  const missing: string[] = [];
  if (browserFlow && !uris.some((u) => u.trim())) missing.push("redirectUris");
  if (tokenAuthMethod === "PRIVATE_KEY_JWT" && !jwksUrl.trim()) missing.push("jwksUrl");

  const cleaned = (xs: string[]) => xs.map((u) => u.trim()).filter(Boolean);
  const dirty = loaded !== null && (
    (loaded.name ?? "") !== name ||
    (loaded.description ?? "") !== description ||
    JSON.stringify(loaded.grantTypes) !== JSON.stringify(grants) ||
    JSON.stringify(loaded.redirectUris) !== JSON.stringify(cleaned(uris)) ||
    JSON.stringify(loaded.postLogoutRedirectUris) !== JSON.stringify(cleaned(logoutUris)) ||
    JSON.stringify(loaded.webOrigins) !== JSON.stringify(cleaned(webOrigins)) ||
    JSON.stringify(loaded.scopes) !== JSON.stringify(scopes) ||
    (loaded.subjectClaim ?? "") !== subjectClaim ||
    (loaded.authFlowAlias ?? "") !== authFlowAlias ||
    loaded.publicClient !== publicClient ||
    loaded.consentRequired !== consentRequired ||
    loaded.displayOnConsentScreen !== displayOnConsent ||
    (loaded.loginTheme ?? "") !== loginTheme ||
    (loaded.rootUrl ?? "") !== rootUrl ||
    (loaded.homeUrl ?? "") !== homeUrl ||
    (loaded.adminUrl ?? "") !== adminUrl ||
    loaded.alwaysDisplayInConsole !== alwaysDisplay ||
    (loaded.accessTokenLifespan != null ? String(loaded.accessTokenLifespan) : "") !== accessLifespan ||
    (loaded.refreshTokenLifespan != null ? String(loaded.refreshTokenLifespan) : "") !== refreshLifespan ||
    (loaded.idTokenSignatureAlg ?? "") !== idTokenAlg ||
    loaded.reuseRefreshTokens !== reuseRefresh ||
    (loaded.tokenEndpointAuthMethod ?? "") !== tokenAuthMethod ||
    (loaded.jwksUrl ?? "") !== jwksUrl ||
    (loaded.backchannelLogoutUri ?? "") !== backchannelLogoutUri ||
    (loaded.frontchannelLogoutUri ?? "") !== frontchannelLogoutUri ||
    (loaded.x509CertificateBoundAccessTokens ?? false) !== certBoundTokens ||
    (loaded.requireSignedRequestObject ?? false) !== requireSignedRequest ||
    (loaded.jarmResponseMode ?? "") !== jarmResponseMode
  );

  const toggleGrant = (v: string, on: boolean) => setGrants((g) => on ? [...new Set([...g, v])] : g.filter((x) => x !== v));
  const toggleScope = (v: string, on: boolean) => setScopes((s) => on ? [...new Set([...s, v])] : s.filter((x) => x !== v));

  const save = async () => {
    if (missing.length) { setAttempted(true); setTab(missing.includes("jwksUrl") ? "keys" : "login"); return; }
    if (!loaded) return;
    setBusy(true);
    const body: ClientWrite = {
      clientId: loaded.clientId,
      applicationId: loaded.applicationId ?? null, // preserve the Application link on save
      name: name || null,
      description: description || null,
      grantTypes: grants,
      redirectUris: cleaned(uris),
      postLogoutRedirectUris: cleaned(logoutUris),
      webOrigins: cleaned(webOrigins),
      scopes,
      subjectClaim: subjectClaim || null,
      authFlowAlias: authFlowAlias || null,
      publicClient,
      consentRequired,
      displayOnConsentScreen: displayOnConsent,
      loginTheme: loginTheme || null,
      rootUrl: rootUrl || null,
      homeUrl: homeUrl || null,
      adminUrl: adminUrl || null,
      alwaysDisplayInConsole: alwaysDisplay,
      accessTokenLifespan: accessLifespan.trim() ? Number(accessLifespan) : null,
      refreshTokenLifespan: refreshLifespan.trim() ? Number(refreshLifespan) : null,
      idTokenSignatureAlg: idTokenAlg || null,
      reuseRefreshTokens: reuseRefresh,
      tokenEndpointAuthMethod: tokenAuthMethod || null,
      jwksUrl: jwksUrl || null,
      backchannelLogoutUri: backchannelLogoutUri.trim() || null,
      frontchannelLogoutUri: frontchannelLogoutUri.trim() || null,
      x509CertificateBoundAccessTokens: certBoundTokens,
      requireSignedRequestObject: requireSignedRequest,
      jarmResponseMode: jarmResponseMode || null,
    };
    try {
      const saved = await api.update(realmId, loaded.id, body);
      hydrate(saved);
      setNote({ tone: "success", title: t("clientDetail.saveSuccess"), message: t("clientDetail.saveSuccessMsg", { clientId: loaded.clientId }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("clientDetail.saveError"), message: String((e as Error).message ?? e) });
    } finally { setBusy(false); }
  };

  const regenerate = async () => {
    if (!loaded) return;
    try {
      const rotated = await api.regenerate(realmId, loaded.id);
      if (rotated.secret) { setNewSecret(rotated.secret); setRevealed(rotated.secret); }
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("clientDetail.regenerateError"), message: String((e as Error).message ?? e) });
    }
  };

  const reveal = async () => {
    if (!loaded) return;
    try {
      const full = await api.reveal(realmId, loaded.id);
      setRevealed(full.secret ?? "");
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("clientDetail.revealError"), message: String((e as Error).message ?? e) });
    }
  };

  const exportClient = () => {
    if (!loaded) return;
    // Export the client's configuration as a portable JSON document (the secret is never included).
    const { secret: _s, id: _i, ...config } = loaded;
    void _s; void _i;
    const blob = new Blob([JSON.stringify(config, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${loaded.clientId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const remove = async () => {
    if (!loaded) return;
    setConfirmDel(false);
    try { await api.remove(realmId, loaded.id); onDeleted(); }
    catch (e: unknown) { setNote({ tone: "error", title: t("clientDetail.deleteError"), message: String((e as Error).message ?? e) }); }
  };

  const TABS = [
    { id: "settings", label: t("clientDetail.tabSettings") },
    { id: "credentials", label: t("clientDetail.tabCredentials") },
    { id: "login", label: t("clientDetail.tabLogin") },
    { id: "scopes", label: t("clientDetail.tabScopes") },
    { id: "mappers", label: t("clientDetail.tabMappers") },
    ...(!publicClient ? [{ id: "keys", label: t("clientDetail.tabKeys") }] : []),
    { id: "roles", label: t("clientDetail.tabRoles") },
    ...(grants.includes("client_credentials") ? [{ id: "serviceaccount", label: t("clientDetail.tabServiceAccount") }] : []),
    ...(workloadIdentityApi ? [{ id: "workloadidentity", label: t("clientDetail.tabWorkloadIdentity") }] : []),
    ...(agentsApi ? [{ id: "agents", label: t("clientDetail.tabAgents") }] : []),
    { id: "authorization", label: t("clientDetail.tabAuthorization") },
    { id: "advanced", label: t("clientDetail.tabAdvanced") },
  ];

  return (
    <Page>
      {!embedded && <button type="button" onClick={onBack} className="hx-backlink">{t("clientDetail.backLink")}</button>}

      {err ? (
        <PageBody>
          <Alert tone="danger" title={t("clientDetail.loadErrorTitle")}>{err}</Alert>
        </PageBody>
      ) : loaded === null ? (
        <PageBody>
          <div className="hx-loadwrap"><Spinner size={28} label={t("clientDetail.loadingClient")} /></div>
        </PageBody>
      ) : (
        <>
          <PageHeader
            title={
              <span className="hx-namecell">
                {clientLabel(loaded)}
                {browserFlow ? <Badge tone="accent">{t("clientDetail.badgeBrowserLogin")}</Badge> : <Badge tone="neutral">{t("clientDetail.badgeService")}</Badge>}
              </span>
            }
            // The raw row UUID is an internal primary key — only useful on the standalone client page,
            // never under an Application (where the app already names the client).
            description={!embedded ? <code className="hx-mono hx-faint">{loaded.id}</code> : undefined}
            actions={
              <>
                {dirty && <span className="hx-unsaved">{t("clientDetail.unsaved")}</span>}
                <RowMenu items={[
                  { label: t("clientDetail.exportJson"), onSelect: () => exportClient() },
                  { label: t("clientDetail.regenerateSecret"), onSelect: regenerate },
                  { label: t("clientDetail.deleteClient"), danger: true, onSelect: () => setConfirmDel(true) },
                ]} />
                <Button variant="ghost" onClick={reload} disabled={!dirty || busy}>{t("clientDetail.discard")}</Button>
                <Button variant="primary" onClick={save} disabled={!dirty || busy}>{t("clientDetail.saveChanges")}</Button>
              </>
            }
          />

          <PageBody>
            <Tabs tabs={TABS} value={tab} onChange={(t2) => setTab(t2 as TabId)} />

            {tab === "settings" && (
              <div className="hx-clientgrid">
                <Section title={t("clientDetail.generalTitle")} description={t("clientDetail.generalDesc")} layout="cols">
                  <FormField label={t("clientDetail.displayName")} hint={t("clientDetail.displayNameHint")}>
                    <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={loaded.clientId} />
                  </FormField>
                  <FormField label={t("clientDetail.description")}>
                    <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("clientDetail.descriptionPlaceholder")} />
                  </FormField>
                  <FormField label={t("clientDetail.rootUrl")} hint={t("clientDetail.rootUrlHint")}>
                    <Input value={rootUrl} onChange={(e) => setRootUrl(e.target.value)} placeholder="https://app.example" />
                  </FormField>
                  <FormField label={t("clientDetail.homeUrl")} hint={t("clientDetail.homeUrlHint")}>
                    <Input value={homeUrl} onChange={(e) => setHomeUrl(e.target.value)} placeholder="https://app.example/" />
                  </FormField>
                  <FormField label={t("clientDetail.adminUrl")} hint={t("clientDetail.adminUrlHint")}>
                    <Input value={adminUrl} onChange={(e) => setAdminUrl(e.target.value)} placeholder="https://app.example/admin" />
                  </FormField>
                  <div className="hx-full"><Checkbox label={t("clientDetail.alwaysDisplay")} checked={alwaysDisplay} onChange={setAlwaysDisplay} /></div>
                </Section>
              </div>
            )}

            {tab === "credentials" && (
              <div className="hx-clientgrid">
                <Section title={t("clientDetail.capabilitiesTitle")} description={t("clientDetail.capabilitiesDesc")}>
                  <Checkbox label={t("clientDetail.publicClient")} checked={publicClient} onChange={setPublicClient} />
                  <p className="hx-help">
                    {publicClient ? t("clientDetail.publicClientHelp") : t("clientDetail.confidentialClientHelp")}
                  </p>
                  <div className="hx-checklist">
                    {GRANT_TYPES.map((g) => (
                      <Checkbox key={g.value} label={g.label} checked={grants.includes(g.value)} onChange={(on) => toggleGrant(g.value, on)} />
                    ))}
                  </div>
                </Section>

                <Section title={t("clientDetail.clientIdSecretTitle")} description={t("clientDetail.clientIdSecretDesc")}>
                  <FormField label={t("clientDetail.clientIdLabel")}>
                    <div className="hx-secret__row">
                      <Input readOnly value={loaded.clientId} aria-label={t("clientDetail.clientIdLabel")} className="hx-mono" />
                      <CopyButton value={loaded.clientId} label={t("clientDetail.copyClientId")} size={38} />
                    </div>
                  </FormField>
                  {publicClient ? (
                    <p className="hx-muted">
                      {t("clientDetail.publicClientNoSecret")}
                    </p>
                  ) : (
                    <FormField label={t("clientDetail.clientSecret")}>
                      <div className="hx-secret">
                        <Input readOnly aria-label={t("clientDetail.clientSecret")} className="hx-mono"
                          value={revealed ?? "••••••••••••••••••••••••••••••••"} />
                        <div className="hx-secret__actions">
                          {revealed === null
                            ? <Button variant="ghost" onClick={reveal}>{t("clientDetail.reveal")}</Button>
                            : <CopyButton value={revealed} label={t("clientDetail.copyClientSecret")} size={38} />}
                          <Button variant="ghost" onClick={regenerate}>{t("clientDetail.regenerate")}</Button>
                        </div>
                      </div>
                      <span className="hx-field__hint">
                        {t("clientDetail.regenerateHint")}
                      </span>
                    </FormField>
                  )}
                </Section>

                <Section title={t("clientDetail.tokenLifetimesTitle")} description={t("clientDetail.tokenLifetimesDesc")} layout="cols">
                  <FormField label={t("clientDetail.accessTokenLifespan")} hint={t("clientDetail.accessTokenLifespanHint")}>
                    <Input type="number" min={0} inputMode="numeric" value={accessLifespan} onChange={(e) => setAccessLifespan(e.target.value)} placeholder={t("clientDetail.inherit3600")} />
                  </FormField>
                  <FormField label={t("clientDetail.refreshTokenLifespan")} hint={t("clientDetail.refreshTokenLifespanHint")}>
                    <Input type="number" min={0} inputMode="numeric" value={refreshLifespan} onChange={(e) => setRefreshLifespan(e.target.value)} placeholder={t("clientDetail.inheritDefault")} />
                  </FormField>
                  <FormField label={t("clientDetail.idTokenAlg")} hint={t("clientDetail.idTokenAlgHint")}>
                    <Select aria-label={t("clientDetail.idTokenAlg")} value={idTokenAlg} onChange={setIdTokenAlg}
                      options={[{ value: "", label: t("clientDetail.rs256Default") }, ...["RS384", "RS512", "ES256", "ES384", "ES512"].map((a) => ({ value: a, label: a }))]} />
                  </FormField>
                  <div className="hx-full"><Checkbox label={t("clientDetail.reuseRefresh")} checked={reuseRefresh} onChange={setReuseRefresh} /></div>
                </Section>
              </div>
            )}

            {tab === "login" && (
              <div className="hx-clientgrid">
                {browserFlow ? (
                  <Section title={t("clientDetail.loginSettingsTitle")} description={t("clientDetail.loginSettingsDesc")}>
                    <FormField label={t("clientDetail.redirectUris")} required error={attempted && missing.includes("redirectUris") ? t("clientDetail.redirectUrisError") : undefined}>
                      <UriList uris={uris} setUris={setUris} placeholder="https://app.example/callback" label={t("clientDetail.redirectUriLabel")} />
                    </FormField>
                    <FormField label={t("clientDetail.postLogoutUris")} hint={t("clientDetail.postLogoutUrisHint")}>
                      <UriList uris={logoutUris} setUris={setLogoutUris} placeholder="https://app.example/" label={t("clientDetail.postLogoutUriLabel")} />
                    </FormField>
                    <FormField label={t("clientDetail.webOrigins")} hint={t("clientDetail.webOriginsHint")}>
                      <UriList uris={webOrigins} setUris={setWebOrigins} placeholder="https://app.example" label={t("clientDetail.webOriginLabel")} />
                    </FormField>
                    <Divider />
                    <FormField label={t("clientDetail.backchannelLogout")} hint={t("clientDetail.backchannelLogoutHint")}>
                      <Input value={backchannelLogoutUri} onChange={(e) => setBackchannelLogoutUri(e.target.value)} placeholder="https://app.example/backchannel-logout" />
                    </FormField>
                    <FormField label={t("clientDetail.frontchannelLogout")} hint={t("clientDetail.frontchannelLogoutHint")}>
                      <Input value={frontchannelLogoutUri} onChange={(e) => setFrontchannelLogoutUri(e.target.value)} placeholder="https://app.example/frontchannel-logout" />
                    </FormField>
                    <Divider />
                    <Checkbox label={t("clientDetail.consentRequired")} checked={consentRequired} onChange={setConsentRequired} />
                    <p className="hx-help">
                      {t("clientDetail.consentRequiredHelp")}
                    </p>
                    {consentRequired && <Checkbox label={t("clientDetail.displayOnConsent")} checked={displayOnConsent} onChange={setDisplayOnConsent} />}
                    <FormField label={t("clientDetail.loginTheme")} hint={t("clientDetail.loginThemeHint")}>
                      <Input value={loginTheme} onChange={(e) => setLoginTheme(e.target.value)} placeholder={t("clientDetail.realmDefaultPlaceholder")} />
                    </FormField>
                  </Section>
                ) : (
                  <Section title={t("clientDetail.loginSettingsTitle")} description={t("clientDetail.loginSettingsOffDesc")}>
                    <p className="hx-muted">
                      {t("clientDetail.noBrowserLoginPre")} <strong>{t("clientDetail.authCodeGrant")}</strong> {t("clientDetail.noBrowserLoginPost")}
                    </p>
                  </Section>
                )}

                <Section title={t("clientDetail.authFlowTitle")} description={t("clientDetail.authFlowDesc")}>
                  <FormField label={t("clientDetail.loginFlow")} hint={t("clientDetail.loginFlowHint")}>
                    <Select aria-label={t("clientDetail.loginFlow")} value={authFlowAlias} onChange={setAuthFlowAlias}
                      options={[
                        { value: "", label: t("clientDetail.inheritBrowserDefault") },
                        ...flows.map((f) => ({ value: f.alias, label: f.builtIn ? `${f.alias}${t("clientDetail.builtIn")}` : f.alias })),
                      ]} />
                  </FormField>
                </Section>
              </div>
            )}

            {tab === "scopes" && (
              <div className="hx-clientgrid">
                <Section title={t("clientDetail.assignedScopesTitle")} description={t("clientDetail.assignedScopesDesc")}>
                  <div className="hx-badges">
                    {SCOPES.map((s) => <Checkbox key={s} label={s} checked={scopes.includes(s)} onChange={(on) => toggleScope(s, on)} />)}
                  </div>
                </Section>
                <Section title={t("clientDetail.scopeClaimsTitle")} description={t("clientDetail.scopeClaimsDesc")}>
                  {scopes.length === 0 ? (
                    <p className="hx-muted">{t("clientDetail.noScopes")}</p>
                  ) : (
                    <div className="hx-colstack">
                      {scopes.map((s) => {
                        const cat = scopeCatalog.find((c) => c.name === s);
                        return (
                          <div key={s} className="hx-scopeclaims">
                            <code className="hx-scopeclaims__name">{s}</code>
                            <div className="hx-scopeclaims__chips">
                              {cat && cat.claimPreview.length > 0
                                ? cat.claimPreview.map((c) => <span key={c} className="hx-chip hx-chip--method">{c}</span>)
                                : <span className="hx-help">{cat ? t("clientDetail.noClaimsMapped") : t("clientDetail.standardOidcScope")}</span>}
                              {cat && cat.claimCount > cat.claimPreview.length && (
                                <span className="hx-help">{t("clientDetail.moreClaims", { count: cat.claimCount - cat.claimPreview.length })}</span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  <p className="hx-help">
                    {t("clientDetail.scopeHintPre")} <strong>{t("clientDetail.clientScopesLink")}</strong> {t("clientDetail.scopeHintPost")}
                  </p>
                </Section>
              </div>
            )}

            {tab === "mappers" && (
              <div className="hx-clientgrid">
                <MappersTab mapperApi={mapperApi} realmId={realmId} clientId={loaded.clientId} catalogue={catalogue}
                  onError={(m) => setNote({ tone: "error", title: t("clientDetail.mapperError"), message: m })} />
              </div>
            )}

            {tab === "keys" && (
              <div className="hx-clientgrid">
                <Section title={t("clientDetail.tokenAuthTitle")} description={t("clientDetail.tokenAuthDesc")} layout={tokenAuthMethod === "PRIVATE_KEY_JWT" ? "cols" : "single"}>
                  <FormField label={t("clientDetail.authenticator")} hint={t("clientDetail.authenticatorHint")}>
                    <Select aria-label={t("clientDetail.authenticator")} value={tokenAuthMethod} onChange={setTokenAuthMethod}
                      options={[
                        { value: "", label: t("clientDetail.clientSecretDefault") },
                        { value: "PRIVATE_KEY_JWT", label: t("clientDetail.signedJwt") },
                      ]} />
                  </FormField>
                  {tokenAuthMethod === "PRIVATE_KEY_JWT" && (
                    <FormField label={t("clientDetail.jwksUrl")} required={tokenAuthMethod === "PRIVATE_KEY_JWT"}
                      hint={t("clientDetail.jwksUrlHint")}
                      error={attempted && tokenAuthMethod === "PRIVATE_KEY_JWT" && !jwksUrl.trim() ? t("clientDetail.jwksUrlError") : undefined}>
                      <Input className="hx-full" value={jwksUrl} onChange={(e) => setJwksUrl(e.target.value)} placeholder="https://app.example/.well-known/jwks.json" />
                    </FormField>
                  )}
                  <p className="hx-full hx-help">
                    {t("clientDetail.keyHelpPart1")} <strong>{t("clientDetail.clientSecretTerm")}</strong>{t("clientDetail.keyHelpPart2")}
                    {t("clientDetail.keyHelpPart1")} <strong>{t("clientDetail.signedJwtTerm")}</strong>{t("clientDetail.keyHelpPart3")} <code>client_assertion</code> JWT
                    {t("clientDetail.keyHelpPart4")}
                  </p>
                </Section>
              </div>
            )}

            {tab === "roles" && (
              <div className="hx-clientgrid">
                <ClientRolesTab clientRoleApi={clientRoleApi} realmId={realmId} clientId={loaded.clientId}
                  onError={(m) => setNote({ tone: "error", title: t("clientDetail.roleError"), message: m })} />
              </div>
            )}

            {tab === "serviceaccount" && (
              <div className="hx-clientgrid">
                <ServiceAccountTab clientRoleApi={clientRoleApi} roleApi={roleApi} realmId={realmId} clientId={loaded.clientId}
                  onError={(m) => setNote({ tone: "error", title: t("clientDetail.saError"), message: m })} />
              </div>
            )}

            {tab === "workloadidentity" && workloadIdentityApi && (
              <WorkloadIdentityPage api={workloadIdentityApi} realmId={realmId}
                boundClientId={loaded.clientId} serviceAccountEnabled={grants.includes("client_credentials")} embedded />
            )}

            {tab === "agents" && agentsApi && (
              <AgentsPage api={agentsApi} realmId={realmId} boundClientId={loaded.clientId} embedded />
            )}

            {tab === "authorization" && (
              <div className="hx-clientgrid">
                <AuthorizationTab authzApi={authzApi} roleApi={roleApi} clientRoleApi={clientRoleApi} realmId={realmId} clientId={loaded.clientId}
                  onError={(m) => setNote({ tone: "error", title: t("clientDetail.authzError"), message: m })} />
              </div>
            )}

            {tab === "advanced" && (
              <div className="hx-clientgrid">
                <Section title={t("clientDetail.tokenClaimsTitle")} description={t("clientDetail.tokenClaimsDesc")}>
                  <FormField label={t("clientDetail.subjectIdentifier")} hint={t("clientDetail.subjectIdentifierHint")}>
                    <Select aria-label={t("clientDetail.subjectIdentifier")} value={subjectClaim} onChange={setSubjectClaim}
                      options={[{ value: "", label: t("clientDetail.inheritRealmDefault") }, ...catalogue.filter((c) => c.key !== "sub").map((c) => ({ value: c.key, label: `${c.label} (${c.key})` }))]} />
                  </FormField>
                </Section>
                {loaded && (
                  <Section title={t("clientDetail.resourceIndicatorsTitle")} description={t("clientDetail.resourceIndicatorsDesc")}>
                    <ResourceIndicatorEditor api={api} realmId={realmId} clientId={loaded.clientId} onNote={setNote} />
                  </Section>
                )}
                <Section title={t("clientDetail.fapiTitle")} description={t("clientDetail.fapiDesc")}>
                  <div className="hx-full">
                    <Checkbox label={t("clientDetail.certBound")}
                      checked={certBoundTokens} onChange={setCertBoundTokens} />
                  </div>
                  <div className="hx-full">
                    <Checkbox label={t("clientDetail.requireSignedRequestLabel")}
                      checked={requireSignedRequest} onChange={setRequireSignedRequest} />
                  </div>
                  <FormField label={t("clientDetail.jarmMode")} hint={t("clientDetail.jarmModeHint")}>
                    <Select aria-label={t("clientDetail.jarmMode")} value={jarmResponseMode} onChange={setJarmResponseMode}
                      options={[
                        { value: "", label: t("clientDetail.jarmPlain") },
                        { value: "jwt", label: "jwt (query)" },
                        { value: "query.jwt", label: "query.jwt" },
                        { value: "fragment.jwt", label: "fragment.jwt" },
                        { value: "form_post.jwt", label: "form_post.jwt" },
                      ]} />
                  </FormField>
                </Section>
              </div>
            )}
          </PageBody>
        </>
      )}

      <Modal open={newSecret !== null} title={t("clientDetail.newSecretTitle")} onClose={() => setNewSecret(null)} width={480}>
        {newSecret && <SecretReveal clientId={loaded?.clientId ?? ""} secret={newSecret} onClose={() => setNewSecret(null)} />}
      </Modal>

      <ConfirmDialog open={confirmDel} title={t("clientDetail.deleteTitle")}
        message={t("clientDetail.deleteMessage", { clientId: loaded?.clientId ?? "" })}
        onConfirm={remove} onCancel={() => setConfirmDel(false)} />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

/** RFC 8707 per-client allow-list editor (Advanced tab). One absolute resource URI per line; empty = any. */
function ResourceIndicatorEditor({ api, realmId, clientId, onNote }: {
  api: ClientApi; realmId: string; clientId: string; onNote: (n: Note) => void;
}) {
  const { t } = useT();
  const [text, setText] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  React.useEffect(() => {
    let live = true;
    api.getAllowedResources(realmId, clientId)
      .then((r) => { if (live) setText((r ?? []).join("\n")); })
      .catch(() => { if (live) setText(""); });
    return () => { live = false; };
  }, [api, realmId, clientId]);
  const save = async () => {
    setSaving(true);
    try {
      const resources = (text ?? "").split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
      await api.setAllowedResources(realmId, clientId, resources);
      onNote({ tone: "success", title: t("clientDetail.allowedResourcesSaved"), message: resources.length ? t("clientDetail.allowedResourcesSavedCount", { count: resources.length }) : t("clientDetail.allowListCleared") });
    } catch (e: unknown) {
      onNote({ tone: "error", title: t("clientDetail.allowedResourcesError"), message: String((e as Error).message ?? e) });
    } finally {
      setSaving(false);
    }
  };
  if (text === null) return <div className="hx-help">{t("clientDetail.loadingShort")}</div>;
  return (
    <FormField label={t("clientDetail.allowedResources")} hint={t("clientDetail.allowedResourcesHint")}>
      <Textarea
        className="hx-mono"
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={4}
        spellCheck={false}
        placeholder={"https://api.example.com/orders\nhttps://billing.example.com"}
      />
      <div className="hx-formactions">
        <Button variant="primary" disabled={saving} onClick={save}>{saving ? t("clientDetail.saving") : t("clientDetail.saveAllowedResources")}</Button>
      </div>
    </FormField>
  );
}

const emptyMapper: MapperWrite = { name: "", mapperType: "USER_ATTRIBUTE", source: "", claimName: "", addToAccessToken: true, addToIdToken: true };

function MappersTab({ mapperApi, realmId, clientId, catalogue, onError }: {
  mapperApi: MapperApi; realmId: string; clientId: string; catalogue: Claim[]; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [rows, setRows] = React.useState<ProtocolMapper[] | null>(null);
  const [editing, setEditing] = React.useState<ProtocolMapper | null>(null);
  const [draft, setDraft] = React.useState<MapperWrite | null>(null);
  const [confirmDel, setConfirmDel] = React.useState<ProtocolMapper | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [attempted, setAttempted] = React.useState(false);

  const reload = React.useCallback(() => {
    setRows(null);
    mapperApi.list(realmId, clientId).then(setRows).catch((e) => { onError(String(e.message ?? e)); setRows([]); });
  }, [mapperApi, realmId, clientId, onError]);
  React.useEffect(reload, [reload]);

  const openNew = () => { setEditing(null); setDraft({ ...emptyMapper }); setAttempted(false); };
  const openEdit = (m: ProtocolMapper) => {
    setEditing(m);
    setDraft({ name: m.name, mapperType: m.mapperType, source: m.source ?? "", claimName: m.claimName, addToAccessToken: m.addToAccessToken, addToIdToken: m.addToIdToken });
    setAttempted(false);
  };

  const translatedMapperTypes = [
    { value: "USER_ATTRIBUTE", label: t("clientDetail.mapperTypeUserAttr") },
    { value: "USER_ROLE", label: t("clientDetail.mapperTypeUserRoles") },
    { value: "HARDCODED", label: t("clientDetail.mapperTypeHardcodedValue") },
  ];

  const valid = draft && draft.name.trim() && draft.claimName.trim() && (draft.mapperType === "USER_ROLE" || (draft.source ?? "").trim());
  const save = async () => {
    if (!draft) return;
    if (!valid) { setAttempted(true); return; }
    setBusy(true);
    const body: MapperWrite = { ...draft, name: draft.name.trim(), claimName: draft.claimName.trim(), source: (draft.source ?? "").trim() };
    try {
      if (editing) await mapperApi.update(realmId, clientId, editing.mapperId, body);
      else await mapperApi.create(realmId, clientId, body);
      setDraft(null); setEditing(null); reload();
    } catch (e: unknown) { onError(String((e as Error).message ?? e)); }
    finally { setBusy(false); }
  };

  const remove = async () => {
    if (!confirmDel) return;
    const m = confirmDel; setConfirmDel(null);
    try { await mapperApi.remove(realmId, clientId, m.mapperId); reload(); }
    catch (e: unknown) { onError(String((e as Error).message ?? e)); }
  };

  const isHardcoded = draft?.mapperType === "HARDCODED";

  return (
    <Section title={t("clientDetail.mappersTitle")}
      description={t("clientDetail.mappersDesc")}
      actions={<Button variant="primary" onClick={openNew}>{t("clientDetail.addMapper")}</Button>}>
      {rows === null ? (
        <div className="hx-loadwrap"><Spinner size={22} label={t("clientDetail.loadingMappers")} /></div>
      ) : rows.length === 0 ? (
        <p className="hx-muted">{t("clientDetail.noMappers")}</p>
      ) : (
        <div className="hx-tablescroll">
          <table className="hx-table">
            <thead><tr><th>{t("clientDetail.mapperColName")}</th><th>{t("clientDetail.mapperColType")}</th><th>{t("clientDetail.mapperColSource")}</th><th>{t("clientDetail.mapperColClaim")}</th><th>{t("clientDetail.mapperColTokens")}</th><th className="hx-col-actions" aria-label="Actions" /></tr></thead>
            <tbody>
              {rows.map((m) => (
                <tr key={m.mapperId}>
                  <td><strong>{m.name}</strong></td>
                  <td>{m.mapperType === "HARDCODED" ? t("clientDetail.mapperTypeHardcoded") : m.mapperType === "USER_ROLE" ? t("clientDetail.mapperTypeUserRoles") : t("clientDetail.mapperTypeUserAttr")}</td>
                  <td>{m.mapperType === "USER_ROLE"
                    ? <span className="hx-help">{t("clientDetail.allRoles")}</span>
                    : <><span className="hx-faint">{m.mapperType === "HARDCODED" ? t("clientDetail.prefixValue") : t("clientDetail.prefixAttr")}</span><code>{m.source}</code></>}</td>
                  <td><code>{m.claimName}</code></td>
                  <td>
                    <span className="hx-badges">
                      {m.addToAccessToken && <span className="hx-chip hx-chip--method">access</span>}
                      {m.addToIdToken && <span className="hx-chip hx-chip--method">id</span>}
                    </span>
                  </td>
                  <td className="hx-cell-right">
                    <RowMenu items={[
                      { label: t("common.edit"), onSelect: () => openEdit(m) },
                      { label: t("common.delete"), danger: true, onSelect: () => setConfirmDel(m) },
                    ]} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal open={draft !== null} title={editing ? t("clientDetail.editMapper") : t("clientDetail.addMapper")} onClose={() => setDraft(null)} width={520}>
        {draft && (
          <div>
            <FormField label={t("clientDetail.mapperNameField")} required error={attempted && !draft.name.trim() ? t("clientDetail.mapperNameRequired") : undefined}>
              <Input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder={t("clientDetail.mapperNamePlaceholder")} />
            </FormField>
            <FormField label={t("clientDetail.mapperTypeField")}>
              <Select aria-label={t("clientDetail.mapperTypeField")} value={draft.mapperType} onChange={(v) => setDraft({ ...draft, mapperType: v })} options={translatedMapperTypes} />
            </FormField>
            {draft.mapperType === "USER_ROLE" ? (
              <p className="hx-help">
                {t("clientDetail.userRoleHelp")}
              </p>
            ) : (
              <>
                <FormField label={isHardcoded ? t("clientDetail.hardcodedValue") : t("clientDetail.userAttribute")} required
                  hint={isHardcoded ? t("clientDetail.hardcodedHint") : t("clientDetail.userAttributeHint")}
                  error={attempted && !(draft.source ?? "").trim() ? t("clientDetail.fieldRequired") : undefined}>
                  {isHardcoded
                    ? <Input value={draft.source ?? ""} onChange={(e) => setDraft({ ...draft, source: e.target.value })} placeholder="gov-tier-1" />
                    : <Input list="hx-attr-list" value={draft.source ?? ""} onChange={(e) => setDraft({ ...draft, source: e.target.value })} placeholder="department" />}
                </FormField>
                <datalist id="hx-attr-list">{catalogue.map((c) => <option key={c.key} value={c.key} />)}</datalist>
              </>
            )}
            <FormField label={t("clientDetail.claimName")} required hint={t("clientDetail.claimNameHint")}
              error={attempted && !draft.claimName.trim() ? t("clientDetail.claimNameRequired") : undefined}>
              <Input value={draft.claimName} onChange={(e) => setDraft({ ...draft, claimName: e.target.value })} placeholder="dept" />
            </FormField>
            <div className="hx-badges">
              <Checkbox label={t("clientDetail.addToAccessToken")} checked={draft.addToAccessToken} onChange={(on) => setDraft({ ...draft, addToAccessToken: on })} />
              <Checkbox label={t("clientDetail.addToIdToken")} checked={draft.addToIdToken} onChange={(on) => setDraft({ ...draft, addToIdToken: on })} />
            </div>
            <div className="hx-formactions hx-formactions--end">
              <Button variant="ghost" onClick={() => setDraft(null)} disabled={busy}>{t("common.cancel")}</Button>
              <Button variant="primary" onClick={save} disabled={busy}>{editing ? t("clientDetail.saveMapper") : t("clientDetail.addMapper")}</Button>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmDialog open={confirmDel !== null} title={t("clientDetail.deleteMapperTitle")}
        message={t("clientDetail.deleteMapperMessage", { name: confirmDel?.name ?? "" })}
        onConfirm={remove} onCancel={() => setConfirmDel(null)} />
    </Section>
  );
}

function ClientRolesTab({ clientRoleApi, realmId, clientId, onError }: {
  clientRoleApi: ClientRoleApi; realmId: string; clientId: string; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [rows, setRows] = React.useState<ClientRole[] | null>(null);
  const [draft, setDraft] = React.useState<{ name: string; description: string } | null>(null);
  const [confirmDel, setConfirmDel] = React.useState<ClientRole | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [attempted, setAttempted] = React.useState(false);

  const reload = React.useCallback(() => {
    setRows(null);
    clientRoleApi.listRoles(realmId, clientId).then(setRows).catch((e) => { onError(String(e.message ?? e)); setRows([]); });
  }, [clientRoleApi, realmId, clientId, onError]);
  React.useEffect(reload, [reload]);

  const save = async () => {
    if (!draft) return;
    if (!draft.name.trim()) { setAttempted(true); return; }
    setBusy(true);
    try { await clientRoleApi.createRole(realmId, clientId, draft.name.trim(), draft.description.trim() || null); setDraft(null); reload(); }
    catch (e: unknown) { onError(String((e as Error).message ?? e)); }
    finally { setBusy(false); }
  };
  const remove = async () => {
    if (!confirmDel) return; const r = confirmDel; setConfirmDel(null);
    try { await clientRoleApi.removeRole(realmId, clientId, r.name); reload(); }
    catch (e: unknown) { onError(String((e as Error).message ?? e)); }
  };

  return (
    <Section title={t("clientDetail.rolesTitle")}
      description={t("clientDetail.rolesDesc")}
      actions={<Button variant="primary" onClick={() => { setDraft({ name: "", description: "" }); setAttempted(false); }}>{t("clientDetail.createRole")}</Button>}>
      {rows === null ? (
        <div className="hx-loadwrap"><Spinner size={22} label={t("clientDetail.loadingRoles")} /></div>
      ) : rows.length === 0 ? (
        <p className="hx-muted">{t("clientDetail.noRoles")}</p>
      ) : (
        <div className="hx-tablescroll">
          <table className="hx-table">
            <thead><tr><th>{t("clientDetail.roleColName")}</th><th>{t("clientDetail.roleColDescription")}</th><th className="hx-col-actions" aria-label="Actions" /></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.roleId}>
                  <td><code>{r.name}</code></td>
                  <td>{r.description ?? <span className="hx-faint">—</span>}</td>
                  <td className="hx-cell-right">
                    <RowMenu items={[{ label: t("common.delete"), danger: true, onSelect: () => setConfirmDel(r) }]} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal open={draft !== null} title={t("clientDetail.createRoleTitle")} onClose={() => setDraft(null)} width={460}>
        {draft && (
          <div>
            <FormField label={t("clientDetail.roleName")} required error={attempted && !draft.name.trim() ? t("clientDetail.roleNameRequired") : undefined}>
              <Input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder={t("clientDetail.roleNamePlaceholder")} />
            </FormField>
            <FormField label={t("clientDetail.roleDesc")}>
              <Input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} placeholder={t("clientDetail.roleDescPlaceholder")} />
            </FormField>
            <div className="hx-formactions hx-formactions--end">
              <Button variant="ghost" onClick={() => setDraft(null)} disabled={busy}>{t("common.cancel")}</Button>
              <Button variant="primary" onClick={save} disabled={busy}>{t("clientDetail.createRole")}</Button>
            </div>
          </div>
        )}
      </Modal>
      <ConfirmDialog open={confirmDel !== null} title={t("clientDetail.deleteRoleTitle")}
        message={t("clientDetail.deleteRoleMessage", { name: confirmDel?.name ?? "" })}
        onConfirm={remove} onCancel={() => setConfirmDel(null)} />
    </Section>
  );
}

function ServiceAccountTab({ clientRoleApi, roleApi, realmId, clientId, onError }: {
  clientRoleApi: ClientRoleApi; roleApi: RoleApi; realmId: string; clientId: string; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [assigned, setAssigned] = React.useState<ServiceAccountRole[] | null>(null);
  const [realmRoles, setRealmRoles] = React.useState<Role[]>([]);
  const [clientRoles, setClientRoles] = React.useState<ClientRole[]>([]);
  const [picker, setPicker] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const reload = React.useCallback(() => {
    setAssigned(null);
    clientRoleApi.listServiceAccountRoles(realmId, clientId).then(setAssigned).catch((e) => { onError(String(e.message ?? e)); setAssigned([]); });
  }, [clientRoleApi, realmId, clientId, onError]);
  React.useEffect(reload, [reload]);
  React.useEffect(() => { roleApi.list(realmId).then(setRealmRoles).catch(() => undefined); }, [roleApi, realmId]);
  React.useEffect(() => { clientRoleApi.listRoles(realmId, clientId).then(setClientRoles).catch(() => undefined); }, [clientRoleApi, realmId, clientId]);

  const has = (name: string, type: string) => (assigned ?? []).some((a) => a.roleName === name && a.roleType === type);
  const assign = async (name: string, type: string) => {
    setBusy(true);
    try { await clientRoleApi.assignServiceAccountRole(realmId, clientId, name, type, type === "CLIENT" ? clientId : null); reload(); }
    catch (e: unknown) { onError(String((e as Error).message ?? e)); }
    finally { setBusy(false); }
  };
  const unassign = async (a: ServiceAccountRole) => {
    setBusy(true);
    try { await clientRoleApi.unassignServiceAccountRole(realmId, clientId, a.roleName, a.roleType); reload(); }
    catch (e: unknown) { onError(String((e as Error).message ?? e)); }
    finally { setBusy(false); }
  };

  const available = [
    ...realmRoles.filter((r) => !has(r.name, "REALM")).map((r) => ({ name: r.name, type: "REALM" as const })),
    ...clientRoles.filter((r) => !has(r.name, "CLIENT")).map((r) => ({ name: r.name, type: "CLIENT" as const })),
  ];

  return (
    <Section title={t("clientDetail.saTitle")}
      description={<>{t("clientDetail.saDescPre")} <code>client_credentials</code> {t("clientDetail.saDescMid")} <code>roles</code> {t("clientDetail.saDescPost")}</>}
      actions={<Button variant="primary" onClick={() => setPicker(true)} title={available.length === 0 ? t("clientDetail.allRolesAssigned") : undefined}>{t("clientDetail.assignRole")}</Button>}>
      {assigned === null ? (
        <div className="hx-loadwrap"><Spinner size={22} label={t("clientDetail.loadingSa")} /></div>
      ) : assigned.length === 0 ? (
        <p className="hx-muted">{t("clientDetail.noSaRoles")}</p>
      ) : (
        <div className="hx-tablescroll">
          <table className="hx-table">
            <thead><tr><th>{t("clientDetail.saColRole")}</th><th>{t("clientDetail.saColType")}</th><th className="hx-col-actions" aria-label="Actions" /></tr></thead>
            <tbody>
              {assigned.map((a) => (
                <tr key={a.id || `${a.roleType}:${a.roleName}`}>
                  <td><code>{a.roleName}</code></td>
                  <td><span className={`hx-chip ${a.roleType === "CLIENT" ? "hx-chip--cond" : "hx-chip--method"}`}>{a.roleType === "CLIENT" ? t("clientDetail.roleTypeClient") : t("clientDetail.roleTypeRealm")}</span></td>
                  <td className="hx-cell-right"><RowMenu items={[{ label: t("clientDetail.unassign"), danger: true, onSelect: () => unassign(a) }]} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal open={picker} title={t("clientDetail.assignRoleTitle")} onClose={() => setPicker(false)} width={480}>
        {available.length === 0 ? (
          <p className="hx-muted">{t("clientDetail.allAssigned")}</p>
        ) : (
          <div className="hx-togglelist">
            {available.map((r) => (
              <div key={`${r.type}:${r.name}`} className="hx-togglerow">
                <span className="hx-namecell">
                  <code>{r.name}</code><span className={`hx-chip ${r.type === "CLIENT" ? "hx-chip--cond" : "hx-chip--method"}`}>{r.type === "CLIENT" ? t("clientDetail.roleTypeClient") : t("clientDetail.roleTypeRealm")}</span>
                </span>
                <Button variant="ghost" disabled={busy} onClick={() => assign(r.name, r.type)}>{t("clientDetail.assign")}</Button>
              </div>
            ))}
          </div>
        )}
        <div className="hx-formactions hx-formactions--end">
          <Button variant="primary" onClick={() => setPicker(false)}>{t("clientDetail.done")}</Button>
        </div>
      </Modal>
    </Section>
  );
}

function UriList({ uris, setUris, placeholder, label }: {
  uris: string[]; setUris: React.Dispatch<React.SetStateAction<string[]>>; placeholder: string; label: string;
}) {
  const { t } = useT();
  return (
    <div className="hx-colstack">
      {uris.map((u, i) => (
        <div key={i} className="hx-inputrow">
          <Input value={u} onChange={(e) => setUris((r) => r.map((x, j) => j === i ? e.target.value : x))} placeholder={placeholder} aria-label={`${label} ${i + 1}`} />
          {uris.length > 1 && (
            <button type="button" className="hx-ghosticon hx-ghosticon--36" aria-label={`Remove ${label} ${i + 1}`} onClick={() => setUris((r) => r.filter((_, j) => j !== i))}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
            </button>
          )}
        </div>
      ))}
      <button type="button" className="hx-addrow" onClick={() => setUris((r) => [...r, ""])}>{t("clientDetail.addUri")}</button>
    </div>
  );
}

export function SecretReveal({ clientId, secret, onClose }: { clientId: string; secret: string; onClose: () => void }) {
  const { t } = useT();
  const [copied, setCopied] = React.useState(false);
  const copy = () => { navigator.clipboard?.writeText(secret).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }); };
  return (
    <div>
      <p className="hx-modal__lede">
        {t("clientDetail.secretStorePre")} <strong>{clientId}</strong>{t("clientDetail.secretStorePost")}
      </p>
      <div className="hx-secret__row">
        <Input readOnly value={secret} aria-label={t("clientDetail.clientSecret")} className="hx-mono" />
        <Button variant="ghost" onClick={copy}>{copied ? t("clientDetail.copied") : t("clientDetail.copy")}</Button>
      </div>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="primary" onClick={onClose}>{t("clientDetail.done")}</Button>
      </div>
    </div>
  );
}
