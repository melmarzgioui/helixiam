import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Tabs } from "../components/Tabs";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { FormField, Input, Select } from "../components/FormField";
import { Checkbox } from "../components/Choice";
import { ClientDetailPage } from "./ClientDetailPage";
import { SamlClientForm } from "./SamlClientsPage";
import { ApplicationApi, Application, applicationId, applicationLabel } from "../api/applications";
import { ClientApi, Client } from "../api/clients";
import { SamlClientApi, SamlClient, SamlClientWrite } from "../api/samlClients";
import { ClaimApi, Claim, ScopeApi } from "../api/scopes";
import { FlowApi, FlowSummary, FlowExecution } from "../api/flows";
import { IdentityProviderApi, IdentityProviderConfig, createHttpClient as createIdpClient } from "../api/client";
import { readIdpRedirect, upsertIdpRedirect, SsoMode, MODE_REDIRECT, MODE_OPTION, MODE_LOCAL_ONLY } from "./idpRedirect";
import { MapperApi } from "../api/mappers";
import { ClientRoleApi } from "../api/clientRoles";
import { RoleApi } from "../api/roles";
import { AuthzApi } from "../api/authz";
import { WorkloadIdentityApi } from "../api/workloadIdentity";
import { AgentApi } from "../api/agents";
import { useT } from "../i18n/LocaleContext";

export interface ApplicationDetailPageProps {
  api: ApplicationApi;
  clientApi: ClientApi;
  samlClientApi: SamlClientApi;
  claimApi: ClaimApi;
  flowApi: FlowApi;
  scopeApi: ScopeApi;
  mapperApi: MapperApi;
  clientRoleApi: ClientRoleApi;
  roleApi: RoleApi;
  authzApi: AuthzApi;
  workloadIdentityApi: WorkloadIdentityApi;
  agentsApi: AgentApi;
  /** Realm identity providers, for the Login tab's "Single sign-on" picker (defaults to the HTTP client). */
  idpApi?: IdentityProviderApi;
  /** Jump to an identity provider's detail page (to edit its attribute mapping). */
  onManageMapping?: (alias: string) => void;
  realmId: string;
  name: string;
  onBack: () => void;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/**
 * One Application, every facet: protocol tabs (OIDC / SAML) where each protocol's full config lives, plus
 * the SHARED Claims + Login-flow tabs that apply to whichever protocol the app uses. WSO2/Okta model.
 */
export function ApplicationDetailPage(props: ApplicationDetailPageProps) {
  const { t } = useT();
  const { api, clientApi, samlClientApi, claimApi, flowApi, realmId, name, onBack, onManageMapping } = props;
  const appId = applicationId(realmId, name);
  const idpApi = React.useMemo(() => props.idpApi ?? createIdpClient(import.meta.env?.VITE_API_BASE ?? ""), [props.idpApi]);

  const [app, setApp] = React.useState<Application | null>(null);
  const [oidc, setOidc] = React.useState<Client | null>(null);
  const [saml, setSaml] = React.useState<SamlClient | null>(null);
  const [catalogue, setCatalogue] = React.useState<Claim[]>([]);
  const [flows, setFlows] = React.useState<FlowSummary[]>([]);
  const [idps, setIdps] = React.useState<IdentityProviderConfig[]>([]);
  // "Sign-in method" for this app. DEFAULT = login page's default (local + every enabled provider).
  const [ssoMode, setSsoMode] = React.useState<"DEFAULT" | "REDIRECT" | "OPTION" | "LOCAL_ONLY">("DEFAULT");
  const [redirectAlias, setRedirectAlias] = React.useState("");   // REDIRECT: the single provider
  const [optionAliases, setOptionAliases] = React.useState<string[]>([]); // OPTION: providers shown as alternatives
  const [ssoBusy, setSsoBusy] = React.useState(false);
  const [tab, setTab] = React.useState("oidc");
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    Promise.all([api.get(realmId, name), clientApi.list(realmId), samlClientApi.list(realmId)])
      .then(([a, clients, sps]) => {
        setApp(a);
        setOidc(clients.find((c) => c.applicationId === appId) ?? null);
        setSaml(sps.find((s) => s.applicationId === appId) ?? null);
      })
      .catch((e) => setNote({ tone: "error", title: t("appDetail.loadError"), message: String(e.message ?? e) }));
  }, [api, clientApi, samlClientApi, realmId, name, appId, t]);
  React.useEffect(reload, [reload]);
  React.useEffect(() => { claimApi.list(realmId).then(setCatalogue).catch(() => {}); flowApi.list(realmId).then(setFlows).catch(() => {}); }, [claimApi, flowApi, realmId]);
  React.useEffect(() => { idpApi.list(realmId).then(setIdps).catch(() => {}); }, [idpApi, realmId]);

  // Read the app's current SSO setting from its bound flow's idp-redirect step (local login only if none).
  const boundAlias = app?.authFlowAlias ?? null;
  React.useEffect(() => {
    const reset = () => { setSsoMode("DEFAULT"); setRedirectAlias(""); setOptionAliases([]); };
    if (!boundAlias) { reset(); return; }
    let live = true;
    flowApi.getByAlias(realmId, boundAlias)
      .then((f) => {
        if (!live) return;
        const s = readIdpRedirect(f.executions);
        if (!s) { reset(); }
        else if (s.mode === MODE_LOCAL_ONLY) { setSsoMode("LOCAL_ONLY"); setRedirectAlias(""); setOptionAliases([]); }
        else if (s.mode === MODE_OPTION) { setSsoMode("OPTION"); setOptionAliases(s.aliases); setRedirectAlias(""); }
        else { setSsoMode("REDIRECT"); setRedirectAlias(s.aliases[0] ?? ""); setOptionAliases([]); }
      })
      .catch(() => { if (live) reset(); });
    return () => { live = false; };
  }, [flowApi, realmId, boundAlias]);

  const saveApp = async (patch: Partial<Application>) => {
    if (!app) return;
    try {
      const next = await api.update(realmId, name, { name, displayName: app.displayName, description: app.description, subjectClaim: app.subjectClaim, authFlowAlias: app.authFlowAlias, enabled: app.enabled, ...patch });
      setApp(next);
      setNote({ tone: "success", title: t("appDetail.updateSuccess") });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("appDetail.saveError"), message: String((e as Error).message ?? e) });
    }
  };

  /**
   * Persist this app's sign-in method as its bound flow's `idp-redirect` step. A `null` setting is the
   * DEFAULT (remove the step → login page shows local + every enabled provider). Any real setting
   * ensures the app has its own editable flow (a copy of `browser`, so password/MFA are preserved) so we
   * never mutate the shared built-in `browser` flow.
   */
  const persistSso = async (setting: { mode: SsoMode; aliases: string[] } | null) => {
    if (!app || ssoBusy) return;
    setSsoBusy(true);
    try {
      const bound = flows.find((f) => f.alias === app.authFlowAlias);
      let target = bound && !bound.builtIn ? bound.alias : null;

      if (setting && !target) {
        // The app needs its own editable flow. Reuse "<name>-sso" if it already exists, else copy browser.
        const dedicated = `${name}-sso`;
        if (!flows.some((f) => f.alias === dedicated)) {
          await flowApi.create(realmId, dedicated, "browser");
          setFlows(await flowApi.list(realmId));
        }
        await saveApp({ authFlowAlias: dedicated });
        target = dedicated;
      }

      if (!setting && !target) return; // inherited default, nothing to clear

      const def = await flowApi.getByAlias(realmId, target!);
      const execs: FlowExecution[] = setting
        ? upsertIdpRedirect(def.executions, setting.mode, setting.aliases)
        : upsertIdpRedirect(def.executions, MODE_REDIRECT, []); // no aliases + non-local ⇒ removes the step
      await flowApi.saveByAlias(realmId, target!, execs);
      setNote({ tone: "success", title: t("appDetail.ssoSaved") });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("appDetail.ssoError"), message: String((e as Error).message ?? e) });
    } finally {
      setSsoBusy(false);
    }
  };

  // Switch the sign-in method; persist immediately once the choice is unambiguous (Redirect/Option wait
  // for a provider before writing anything).
  const changeSsoMode = (m: "DEFAULT" | "REDIRECT" | "OPTION" | "LOCAL_ONLY") => {
    setSsoMode(m);
    if (m === "DEFAULT") persistSso(null);
    else if (m === "LOCAL_ONLY") persistSso({ mode: MODE_LOCAL_ONLY, aliases: [] });
    else if (m === "REDIRECT" && redirectAlias) persistSso({ mode: MODE_REDIRECT, aliases: [redirectAlias] });
    else if (m === "OPTION" && optionAliases.length) persistSso({ mode: MODE_OPTION, aliases: optionAliases });
  };
  const pickRedirect = (alias: string) => {
    setRedirectAlias(alias);
    persistSso(alias ? { mode: MODE_REDIRECT, aliases: [alias] } : null);
  };
  const toggleOption = (alias: string, on: boolean) => {
    const next = on ? [...optionAliases, alias] : optionAliases.filter((a) => a !== alias);
    setOptionAliases(next);
    persistSso(next.length ? { mode: MODE_OPTION, aliases: next } : null);
  };
  const selectedAliases = ssoMode === "REDIRECT" ? (redirectAlias ? [redirectAlias] : [])
    : ssoMode === "OPTION" ? optionAliases : [];

  const saveSaml = async (w: SamlClientWrite, isNew: boolean) => {
    try {
      const body = { ...w, applicationId: appId }; // always keep the link to this app
      if (isNew) await samlClientApi.create(realmId, body);
      else await samlClientApi.update(realmId, w.entityId, body);
      setNote({ tone: "success", title: isNew ? t("appDetail.samlAttached") : t("appDetail.samlUpdated") });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("appDetail.samlSaveError"), message: String((e as Error).message ?? e) });
    }
  };

  const addOidc = async (clientId: string) => {
    try {
      await clientApi.create(realmId, {
        clientId, grantTypes: ["authorization_code", "refresh_token"], redirectUris: ["https://"], scopes: ["openid"],
        publicClient: false, tokenEndpointAuthMethod: "client_secret_basic", applicationId: appId,
      });
      setNote({ tone: "success", title: t("appDetail.oidcAttached"), message: t("appDetail.oidcAttachedMessage") });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("appDetail.oidcAttachError"), message: String((e as Error).message ?? e) });
    }
  };

  if (!app) {
    return (
      <Page>
        <button type="button" onClick={onBack} className="hx-backlink">{t("appDetail.backLink")}</button>
        <PageBody>
          <div className="hx-loadwrap"><Spinner size={28} label={t("appDetail.loading")} /></div>
        </PageBody>
      </Page>
    );
  }

  const TABS = [
    { id: "oidc", label: t("appDetail.tabOidc") },
    { id: "saml", label: t("appDetail.tabSaml") },
    { id: "claims", label: t("appDetail.tabClaims") },
    { id: "login", label: t("appDetail.tabLogin") },
    { id: "settings", label: t("appDetail.tabSettings") },
  ];

  return (
    <Page>
      <button type="button" onClick={onBack} className="hx-backlink">{t("appDetail.backLink")}</button>

      <PageHeader
        title={<>{applicationLabel(app)} {oidc && <Badge tone="accent">OIDC</Badge>} {saml && <Badge tone="accent">SAML</Badge>}</>}
        description={
          <>
            {app.displayName && app.displayName.trim()
              ? <><span className="hx-mono hx-faint">{app.name}</span><br /></>
              : null}
            {app.description || t("appDetail.defaultDescription")}
          </>
        }
      />

      <PageBody>
        <Tabs tabs={TABS} value={tab} onChange={setTab} />

        {tab === "oidc" && (
          oidc ? (
            <ClientDetailPage api={clientApi} claimApi={claimApi} flowApi={flowApi} scopeApi={props.scopeApi}
              mapperApi={props.mapperApi} clientRoleApi={props.clientRoleApi} roleApi={props.roleApi} authzApi={props.authzApi}
              workloadIdentityApi={props.workloadIdentityApi} agentsApi={props.agentsApi}
              realmId={realmId} clientId={oidc.id} onBack={() => setTab("oidc")} onDeleted={reload} embedded />
          ) : (
            <AttachProtocol kind={t("appDetail.oidcKind")} placeholder="gov-portal-web" label={t("appDetail.clientIdLabel")} onAdd={addOidc} />
          )
        )}

        {tab === "saml" && (
          <SamlClientForm initial={saml} onSubmit={(w) => saveSaml(w, saml === null)} onCancel={onBack}
            samlApi={samlClientApi} realmId={realmId} apiBase={import.meta.env?.VITE_API_BASE ?? ""} />
        )}

        {tab === "claims" && (
          <Section title={t("appDetail.sharedClaimsTitle")} description={t("appDetail.sharedClaimsDesc")}>
            <FormField label={t("appDetail.subjectIdentifier")} hint={t("appDetail.subjectIdentifierHint")}>
              <Select aria-label={t("appDetail.subjectIdentifier")} value={app.subjectClaim ?? ""} onChange={(v) => saveApp({ subjectClaim: v || null })}
                options={[{ value: "", label: t("appDetail.inheritRealmDefault") }, ...catalogue.filter((c) => c.key !== "sub").map((c) => ({ value: c.key, label: `${c.label} (${c.key})` }))]} />
            </FormField>
            <p className="hx-help">{t("appDetail.sharedClaimsNote")}</p>
          </Section>
        )}

        {tab === "login" && (
          <>
            <Section title={t("appDetail.sharedLoginTitle")} description={t("appDetail.sharedLoginDesc")}>
              <FormField label={t("appDetail.loginFlowLabel")} hint={t("appDetail.loginFlowHint")}>
                <Select aria-label={t("appDetail.loginFlowLabel")} value={app.authFlowAlias ?? ""} onChange={(v) => saveApp({ authFlowAlias: v || null })}
                  options={[{ value: "", label: t("appDetail.inheritBrowserDefault") }, ...flows.map((f) => ({ value: f.alias, label: f.builtIn ? `${f.alias}${t("appDetail.builtInSuffix")}` : f.alias }))]} />
              </FormField>
            </Section>

            <Section title={t("appDetail.ssoTitle")} description={t("appDetail.ssoDesc")}>
              <FormField label={t("appDetail.ssoMethodLabel")} hint={t("appDetail.ssoMethodHint")}>
                <Select aria-label={t("appDetail.ssoMethodLabel")} value={ssoMode} disabled={ssoBusy}
                  onChange={(v) => changeSsoMode(v as "DEFAULT" | "REDIRECT" | "OPTION" | "LOCAL_ONLY")}
                  options={[
                    { value: "DEFAULT", label: t("appDetail.ssoMethodDefault") },
                    { value: "REDIRECT", label: t("appDetail.ssoMethodRedirect") },
                    { value: "OPTION", label: t("appDetail.ssoMethodOption") },
                    { value: "LOCAL_ONLY", label: t("appDetail.ssoMethodLocal") },
                  ]} />
              </FormField>

              {(ssoMode === "REDIRECT" || ssoMode === "OPTION") && idps.length === 0 && (
                <p className="hx-help">{t("appDetail.ssoNoProviders")}</p>
              )}

              {ssoMode === "REDIRECT" && idps.length > 0 && (
                <FormField label={t("appDetail.ssoProviderLabel")} hint={t("appDetail.ssoRedirectHint")}>
                  <Select aria-label={t("appDetail.ssoProviderLabel")} value={redirectAlias} disabled={ssoBusy}
                    onChange={pickRedirect}
                    options={[{ value: "", label: t("appDetail.ssoChooseProvider") }, ...idps.map((p) => ({ value: p.alias, label: `${p.displayName} (${p.alias})` }))]} />
                </FormField>
              )}

              {ssoMode === "OPTION" && idps.length > 0 && (
                <FormField label={t("appDetail.ssoProvidersLabel")} hint={t("appDetail.ssoOptionHint")}>
                  <div className="hx-checklist">
                    {idps.map((p) => (
                      <Checkbox key={p.alias} label={`${p.displayName} (${p.alias})`} disabled={ssoBusy}
                        checked={optionAliases.includes(p.alias)} onChange={(on) => toggleOption(p.alias, on)} />
                    ))}
                  </div>
                </FormField>
              )}

              {selectedAliases.length > 0 && onManageMapping && (
                <>
                  <p className="hx-help">{t("appDetail.ssoMappingHint")}</p>
                  <div className="hx-formactions">
                    {selectedAliases.map((a) => (
                      <Button key={a} variant="ghost" onClick={() => onManageMapping(a)}>
                        {t("appDetail.ssoManageMappingFor", { name: idps.find((p) => p.alias === a)?.displayName ?? a })}
                      </Button>
                    ))}
                  </div>
                </>
              )}
            </Section>
          </>
        )}

        {tab === "settings" && (
          <Section title={t("appDetail.generalTitle")} description={t("appDetail.generalDesc")}>
            <FormField label={t("appDetail.displayNameLabel")} hint={t("appDetail.displayNameHint")}>
              <Input value={app.displayName ?? ""} onChange={(e) => setApp({ ...app, displayName: e.target.value })} onBlur={() => saveApp({ displayName: app.displayName })} placeholder={app.name} />
            </FormField>
            <FormField label={t("appDetail.identifierLabel")} hint={t("appDetail.identifierHint")}>
              <Input value={app.name} disabled />
            </FormField>
            <FormField label={t("appDetail.descriptionLabel")}><Input value={app.description ?? ""} onChange={(e) => setApp({ ...app, description: e.target.value })} onBlur={() => saveApp({ description: app.description })} /></FormField>
            <div className="hx-field"><Checkbox label={t("appDetail.enabledLabel")} checked={app.enabled} onChange={(on) => saveApp({ enabled: on })} /></div>
            <div className="hx-formactions"><Button variant="danger" onClick={async () => {
              if (!window.confirm(t("appDetail.deleteConfirm", { name: applicationLabel(app) }))) return;
              try { await api.remove(realmId, name); onBack(); } catch (e: unknown) { setNote({ tone: "error", title: t("appDetail.deleteError"), message: String((e as Error).message ?? e) }); }
            }}>{t("appDetail.deleteButton")}</Button></div>
          </Section>
        )}
      </PageBody>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

function AttachProtocol({ kind, label, placeholder, onAdd }: { kind: string; label: string; placeholder: string; onAdd: (v: string) => void }) {
  const { t } = useT();
  const [v, setV] = React.useState("");
  return (
    <Section title={t("appDetail.noProtocol", { kind })} description={t("appDetail.attachProtocolDesc", { kind })}>
      <FormField label={label}><Input value={v} onChange={(e) => setV(e.target.value)} placeholder={placeholder} /></FormField>
      <div className="hx-formactions"><Button variant="primary" onClick={() => v.trim() && onAdd(v.trim())}>{t("appDetail.addProtocol", { kind })}</Button></div>
    </Section>
  );
}
