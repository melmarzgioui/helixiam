/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { RowMenu } from "../components/RowMenu";
import { Tabs } from "../components/Tabs";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { Alert } from "../components/Alert";
import { FormField, Input, Textarea } from "../components/FormField";
import { Select } from "../components/Select";
import { Checkbox } from "../components/Choice";
import { ConfirmDialog } from "../components/Modal";
import { ProviderLogo, ProviderKind } from "../components/ProviderLogo";
import { findProviderType, AttributeMapper, ProtocolFamily } from "../components/providerCatalog";
import { IdentityProviderApi, IdentityProviderConfig } from "../api/client";
import { isEidScheme, eidFacilitatedConfig, EidScheme } from "../api/eidCatalog";
import { useT } from "../i18n/LocaleContext";

export interface ConnectionDetailPageProps {
  api: IdentityProviderApi;
  realmId: string;
  alias: string;
  onBack: () => void;
  onDeleted?: () => void;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/** Which protocol family a stored connection belongs to (eID schemes are SAML under the hood). */
function familyOf(protocol: string): ProtocolFamily | "eid" {
  const p = protocol.toLowerCase();
  if (isEidScheme(p)) return "eid";
  if (p === "saml" || p === "saml2") return "saml";
  if (p === "ldap" || p === "ad") return "ldap";
  return "oidc";
}

function kindOf(protocol: string): ProviderKind {
  const known: ProviderKind[] = ["digid", "eherkenning", "eidas", "oidc", "saml", "ldap", "google", "microsoft", "github"];
  return findProviderType(protocol)?.kind ?? (known.includes(protocol as ProviderKind) ? (protocol as ProviderKind) : "social");
}

const serializeMappers = (m: AttributeMapper[]) =>
  m.filter((x) => x.source.trim() && x.target.trim())
    // A self-map (source === target) serialises back to the bare attribute, so a stored "NameID"
    // round-trips to "NameID" (not "NameID=NameID") and the form isn't falsely marked dirty on load.
    .map((x) => (x.source.trim() === x.target.trim() ? x.source.trim() : `${x.source.trim()}=${x.target.trim()}`))
    .join(",");

const parseMappers = (s?: string): AttributeMapper[] =>
  (s ?? "").split(",").map((x) => x.trim()).filter(Boolean).map((pair) => {
    const i = pair.indexOf("=");
    return i >= 0 ? { source: pair.slice(0, i), target: pair.slice(i + 1) } : { source: pair, target: pair };
  });

/**
 * Full-page identity-provider editor (replaces the edit modal). Exposes every backend-honored config key
 * per protocol — OIDC, SAML2 broker, LDAP, and the facilitated eID schemes (DigiD / eHerkenning / eIDAS).
 */
export function ConnectionDetailPage({ api, realmId, alias, onBack, onDeleted }: ConnectionDetailPageProps) {
  const { t } = useT();

  const BINDINGS = [
    { value: "post", label: t("connectionDetail.bindingPost") },
    { value: "redirect", label: t("connectionDetail.bindingRedirect") },
  ];
  const RESPONSE_BINDINGS = [
    { value: "post", label: t("connectionDetail.responseBindingPost") },
    { value: "artifact", label: t("connectionDetail.responseBindingArtifact") },
  ];

  const [loaded, setLoaded] = React.useState<IdentityProviderConfig | null>(null);
  const [err, setErr] = React.useState<string | null>(null);
  const [displayName, setDisplayName] = React.useState("");
  const [enabled, setEnabled] = React.useState(true);
  const [config, setConfig] = React.useState<Record<string, string>>({});
  const [mappers, setMappers] = React.useState<AttributeMapper[]>([]);
  const [tab, setTab] = React.useState("settings");
  const [busy, setBusy] = React.useState(false);
  const [confirmDel, setConfirmDel] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);
  const [attempted, setAttempted] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);

  const runSync = async () => {
    setSyncing(true);
    try {
      const r = await api.syncUsers(realmId, alias);
      setNote({
        tone: r.failed && !r.synced ? "error" : "success",
        title: t("connectionDetail.ldapSyncComplete"),
        message: t("connectionDetail.syncResult", { synced: r.synced, failed: r.failed }) + (r.errors.length ? ` — ${r.errors[0]}` : ""),
      });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("connectionDetail.errSync"), message: String((e as Error).message ?? e) });
    } finally {
      setSyncing(false);
    }
  };

  const hydrate = React.useCallback((c: IdentityProviderConfig) => {
    setLoaded(c);
    setDisplayName(c.displayName ?? "");
    setEnabled(c.enabled);
    const { mappers: serial, ...rest } = c.config ?? {};
    setConfig(rest);
    setMappers(parseMappers(serial));
  }, []);

  const reload = React.useCallback(() => {
    setErr(null); setLoaded(null);
    api.get(realmId, alias)
      .then((c) => { if (c) hydrate(c); else setErr(t("connectionDetail.errNotFound", { alias })); })
      .catch((e) => setErr(String(e.message ?? e)));
  }, [api, realmId, alias, hydrate]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(reload, [reload]);

  const family = loaded ? familyOf(loaded.protocol) : "oidc";
  const type = loaded ? findProviderType(loaded.protocol) : undefined;
  const scheme = (loaded && isEidScheme(loaded.protocol.toLowerCase()) ? loaded.protocol.toLowerCase() : (config.scheme || "")) as EidScheme | "";
  // Login-button preview mark: prefer the eID scheme inferred from the name/alias (eHerkenning/eIDAS are
  // stored as protocol "oidc", so kindOf alone would miss them), else fall back to the protocol's kind.
  const previewKind: ProviderKind =
    (["digid", "eherkenning", "eidas"] as const).find((k) => `${alias} ${displayName}`.toLowerCase().includes(k))
    ?? (loaded ? kindOf(loaded.protocol) : "social");

  const set = (k: string, v: string) => setConfig((c) => ({ ...c, [k]: v }));

  const dirty = !!loaded && (
    displayName !== (loaded.displayName ?? "") ||
    enabled !== loaded.enabled ||
    JSON.stringify({ ...config, ...(serializeMappers(mappers) ? { mappers: serializeMappers(mappers) } : {}) }) !==
      JSON.stringify(loaded.config ?? {})
  );

  // Required-field check (mirrors the wizard's, but against the backend-honored keys).
  const missing = (): string[] => {
    const has = (k: string) => !!(config[k] ?? "").trim();
    const m: string[] = [];
    if (!displayName.trim()) m.push("displayName");
    if (family === "oidc") { if (!has("issuer")) m.push("issuer"); if (!has("clientId")) m.push("clientId"); }
    if (family === "saml" || family === "eid") {
      if (!has("idpEntityId")) m.push("idpEntityId");
      if (!has("ssoUrl")) m.push("ssoUrl");
      if (!has("spEntityId")) m.push("spEntityId");
    }
    if (family === "eid" && !has("minimumLoa")) m.push("minimumLoa");
    if (family === "ldap") { if (!has("url")) m.push("url"); if (!has("bindDn")) m.push("bindDn"); }
    return m;
  };
  const errs = missing();
  const fieldErr = (k: string) => (attempted && errs.includes(k) ? t("connectionDetail.fieldRequired") : undefined);

  const save = async () => {
    if (!loaded) return;
    setAttempted(true);
    if (errs.length) { setTab("settings"); return; }
    setBusy(true);
    try {
      const serial = serializeMappers(mappers);
      await api.update(realmId, alias, {
        alias, protocol: loaded.protocol, displayName, enabled,
        config: { ...config, ...(serial ? { mappers: serial } : {}) },
      });
      setNote({ tone: "success", title: t("connectionDetail.toastSaved"), message: t("connectionDetail.toastSavedMsg", { name: displayName || alias }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("connectionDetail.errSave"), message: String((e as Error).message ?? e) });
    } finally { setBusy(false); }
  };

  const remove = async () => {
    setConfirmDel(false);
    try { await api.remove(realmId, alias); onDeleted?.(); onBack(); }
    catch (e: unknown) { setNote({ tone: "error", title: t("connectionDetail.errDelete"), message: String((e as Error).message ?? e) }); }
  };

  const applyEidDefaults = () => {
    if (!scheme) return;
    const defaults = eidFacilitatedConfig(scheme);
    // Only fill empties — never clobber what the admin already entered.
    setConfig((c) => {
      const next = { ...c };
      for (const [k, v] of Object.entries(defaults)) if (v && !(next[k] ?? "").trim()) next[k] = v;
      return next;
    });
    setNote({ tone: "info", title: t("connectionDetail.toastDefaultsApplied"), message: t("connectionDetail.toastDefaultsAppliedMsg") });
  };

  if (err) return (
    <Page>
      <button type="button" onClick={onBack} className="hx-backlink">{t("connectionDetail.backLink")}</button>
      <PageBody>
        <Alert tone="danger">{err}</Alert>
      </PageBody>
    </Page>
  );

  if (!loaded) return (
    <Page>
      <button type="button" onClick={onBack} className="hx-backlink">{t("connectionDetail.backLink")}</button>
      <PageBody>
        <div className="hx-loadwrap"><Spinner size={28} label={t("connectionDetail.loadingConn")} /></div>
      </PageBody>
    </Page>
  );

  const TABS = family === "oidc"
    ? [{ id: "settings", label: t("connectionDetail.tabSettings") }, { id: "connection", label: t("connectionDetail.tabConnection") }, { id: "mappers", label: t("connectionDetail.tabMappers") }]
    : family === "saml"
      ? [{ id: "settings", label: t("connectionDetail.tabSettings") }, { id: "connection", label: t("connectionDetail.tabConnection") }, { id: "signing", label: t("connectionDetail.tabSigning") }, { id: "attributes", label: t("connectionDetail.tabAttributes") }]
      : family === "eid"
        ? [{ id: "settings", label: t("connectionDetail.tabSettings") }, { id: "eid", label: t("connectionDetail.tabEid") }, { id: "connection", label: t("connectionDetail.tabConnection") }, { id: "certs", label: t("connectionDetail.tabCerts") }]
        : [{ id: "settings", label: t("connectionDetail.tabSettings") }, { id: "connection", label: t("connectionDetail.tabConnection") }, { id: "search", label: t("connectionDetail.tabSearch") }];

  const protoLabel = family === "eid" ? "SAML2 · eID" : family.toUpperCase();

  return (
    <Page>
      <button type="button" onClick={onBack} className="hx-backlink">{t("connectionDetail.backLink")}</button>

      <PageHeader
        title={
          <span className="hx-namecell">
            <ProviderLogo kind={kindOf(loaded.protocol)} size={40} />
            {displayName || alias} <Badge tone="neutral">{protoLabel}</Badge>
          </span>
        }
        description={<span className="hx-mono hx-faint">{alias}</span>}
        actions={
          <>
            {dirty && <span className="hx-unsaved">{t("connectionDetail.unsaved")}</span>}
            <RowMenu items={[{ label: t("connectionDetail.menuDelete"), danger: true, onSelect: () => setConfirmDel(true) }]} />
            <Button variant="ghost" onClick={reload} disabled={!dirty || busy}>{t("connectionDetail.discard")}</Button>
            <Button variant="primary" onClick={save} disabled={!dirty || busy}>{t("connectionDetail.saveChanges")}</Button>
          </>
        }
      />

      <PageBody>
        <Tabs tabs={TABS} value={tab} onChange={setTab} />

        {tab === "settings" && (
          <Section title={t("connectionDetail.sectionGeneralTitle")} description={t("connectionDetail.sectionGeneralDesc")}>
            <FormField label={t("connectionDetail.fieldAlias")} hint={t("connectionDetail.fieldAliasHint")}>
              <Input value={alias} disabled />
            </FormField>
            <FormField label={t("connectionDetail.fieldDisplayName")} required error={fieldErr("displayName")} hint={t("connectionDetail.fieldDisplayNameHint")}>
              <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            </FormField>
            <FormField label={t("connectionDetail.fieldLogoUrl")} hint={t("connectionDetail.fieldLogoUrlHint")}>
              <Input value={config.logoUrl ?? ""} onChange={(e) => set("logoUrl", e.target.value)} placeholder="https://…/logo.svg" />
            </FormField>
            <div className="hx-field">
              <div className="hx-field__label">{t("connectionDetail.logoPreview")}</div>
              <span className="hx-namecell">
                {config.logoUrl?.trim()
                  ? <img src={config.logoUrl} alt="" style={{ height: 26, width: "auto", maxWidth: 120, objectFit: "contain" }} />
                  : <ProviderLogo kind={previewKind} size={28} />}
                <span>{displayName || alias}</span>
              </span>
            </div>
            <Checkbox label={t("connectionDetail.fieldEnabledLabel")} checked={enabled} onChange={setEnabled} />
          </Section>
        )}

        {/* ---- OIDC ---- */}
        {family === "oidc" && tab === "connection" && (
          <>
            <Section title={t("connectionDetail.sectionEndpointsTitle")} description={t("connectionDetail.sectionEndpointsDesc")} layout="cols">
              <div className="hx-full"><FormField label={t("connectionDetail.fieldIssuer")} required error={fieldErr("issuer")} hint={t("connectionDetail.fieldIssuerHint")}>
                <Input value={config.issuer ?? ""} onChange={(e) => set("issuer", e.target.value)} placeholder="https://accounts.example.com" />
              </FormField></div>
              <FormField label={t("connectionDetail.fieldAuthEndpoint")} hint={t("connectionDetail.fieldOverridesDiscovery")}><Input value={config.authorizationEndpoint ?? ""} onChange={(e) => set("authorizationEndpoint", e.target.value)} placeholder="https://…/authorize" /></FormField>
              <FormField label={t("connectionDetail.fieldTokenEndpoint")} hint={t("connectionDetail.fieldOverridesDiscovery")}><Input value={config.tokenEndpoint ?? ""} onChange={(e) => set("tokenEndpoint", e.target.value)} placeholder="https://…/token" /></FormField>
              <FormField label={t("connectionDetail.fieldJwksUri")} hint={t("connectionDetail.fieldJwksUriHint")}><Input value={config.jwksUri ?? ""} onChange={(e) => set("jwksUri", e.target.value)} placeholder="https://…/jwks" /></FormField>
              <FormField label={t("connectionDetail.fieldScopes")} hint={t("connectionDetail.fieldScopesHint")}><Input value={config.scopes ?? ""} onChange={(e) => set("scopes", e.target.value)} placeholder="openid profile email" /></FormField>
            </Section>
            <Section title={t("connectionDetail.sectionClientCredsTitle")} description={t("connectionDetail.sectionClientCredsDesc")} layout="cols">
              <FormField label={t("connectionDetail.fieldClientId")} required error={fieldErr("clientId")}><Input value={config.clientId ?? ""} onChange={(e) => set("clientId", e.target.value)} /></FormField>
              <FormField label={t("connectionDetail.fieldClientSecret")} hint={t("connectionDetail.fieldClientSecretHint")}><Input type="password" value={config.clientSecret ?? ""} onChange={(e) => set("clientSecret", e.target.value)} placeholder="••••••••" /></FormField>
            </Section>
          </>
        )}

        {/* ---- SAML2 broker ---- */}
        {family === "saml" && tab === "connection" && (
          <Section title={t("connectionDetail.sectionSamlEndpointsTitle")} description={t("connectionDetail.sectionSamlEndpointsDesc")} layout="cols">
            <div className="hx-full"><FormField label={t("connectionDetail.fieldIdpEntityId")} required error={fieldErr("idpEntityId")} hint={t("connectionDetail.fieldIdpEntityIdHint")}>
              <Input value={config.idpEntityId ?? ""} onChange={(e) => set("idpEntityId", e.target.value)} placeholder="https://idp.example/metadata" />
            </FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldSsoUrl")} required error={fieldErr("ssoUrl")} hint={t("connectionDetail.fieldSsoUrlHint")}>
              <Input value={config.ssoUrl ?? ""} onChange={(e) => set("ssoUrl", e.target.value)} placeholder="https://idp.example/sso" />
            </FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldSpEntityId")} required error={fieldErr("spEntityId")} hint={t("connectionDetail.fieldSpEntityIdHint")}>
              <Input value={config.spEntityId ?? ""} onChange={(e) => set("spEntityId", e.target.value)} placeholder="https://helix.example/sp" />
            </FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldAcsUrl")} hint={t("connectionDetail.fieldAcsUrlHint")}>
              <Input value={config.assertionConsumerServiceUrl ?? ""} onChange={(e) => set("assertionConsumerServiceUrl", e.target.value)} placeholder="https://helix.example/realms/…/broker/{alias}/acs" />
            </FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldSloUrl")} hint={t("connectionDetail.fieldSloUrlHint")}>
              <Input value={config.singleLogoutServiceUrl ?? ""} onChange={(e) => set("singleLogoutServiceUrl", e.target.value)} placeholder="https://idp.example/slo" />
            </FormField></div>
          </Section>
        )}
        {family === "saml" && tab === "signing" && (
          <Section title={t("connectionDetail.sectionIdpCertTitle")} description={t("connectionDetail.sectionIdpCertDesc")}>
            <FormField label={t("connectionDetail.fieldCertPem")}>
              <Textarea className="hx-mono" value={config.idpSigningCertificate ?? ""} onChange={(e) => set("idpSigningCertificate", e.target.value)} rows={6} placeholder="-----BEGIN CERTIFICATE-----…" />
            </FormField>
          </Section>
        )}
        {family === "saml" && tab === "attributes" && (
          <>
            <Section title={t("connectionDetail.sectionAttrNamesTitle")} description={t("connectionDetail.sectionAttrNamesDesc")} layout="cols">
              <FormField label={t("connectionDetail.fieldEmailAttr")}><Input value={config.emailAttribute ?? ""} onChange={(e) => set("emailAttribute", e.target.value)} placeholder="email" /></FormField>
              <FormField label={t("connectionDetail.fieldFirstNameAttr")}><Input value={config.firstNameAttribute ?? ""} onChange={(e) => set("firstNameAttribute", e.target.value)} placeholder="givenName" /></FormField>
              <FormField label={t("connectionDetail.fieldLastNameAttr")}><Input value={config.lastNameAttribute ?? ""} onChange={(e) => set("lastNameAttribute", e.target.value)} placeholder="surname" /></FormField>
            </Section>
            <Section title={t("connectionDetail.sectionCustomMappersTitle")} description={t("connectionDetail.sectionCustomMappersDesc")}>
              <MapperEditor mappers={mappers} setMappers={setMappers} />
            </Section>
          </>
        )}

        {/* ---- eID (facilitated) ---- */}
        {family === "eid" && tab === "eid" && (
          <>
            <Section title={t("connectionDetail.sectionSchemeDefaultsTitle")} description={`${t("connectionDetail.sectionSchemeDefaultsDescPre")} ${type?.name ?? scheme} ${t("connectionDetail.sectionSchemeDefaultsDescPost")}`}>
              <div className="hx-toolbar">
                <Badge tone="accent">{type?.name ?? scheme}</Badge>
                <Button variant="ghost" onClick={applyEidDefaults}>{t("connectionDetail.applyDefaults")}</Button>
              </div>
            </Section>
            <Section title={t("connectionDetail.sectionAssuranceTitle")} description={t("connectionDetail.sectionAssuranceDesc")} layout="cols">
              {type?.loaOptions && (
                <FormField label={t("connectionDetail.fieldMinLoa")} required error={fieldErr("minimumLoa")} hint={`${t("connectionDetail.fieldMinLoaHintPre")} ${type.name.replace(/\s*\(.*\)/, "")} ${t("connectionDetail.fieldMinLoaHintPost")}`}>
                  <Select aria-label={t("connectionDetail.fieldMinLoa")} value={config.minimumLoa ?? type.defaultLoaValue ?? ""} onChange={(v) => set("minimumLoa", v)}
                    options={type.loaOptions.map((o) => ({ value: o.value, label: o.label, description: o.description }))} />
                </FormField>
              )}
              <FormField label={t("connectionDetail.fieldBinding")} hint={t("connectionDetail.fieldBindingHint")}><Select aria-label={t("connectionDetail.fieldBinding")} value={config.binding ?? "post"} onChange={(v) => set("binding", v)} options={BINDINGS} /></FormField>
              <div className="hx-full"><FormField label={t("connectionDetail.fieldSubjectAttr")} hint={t("connectionDetail.fieldSubjectAttrHint")}>
                <Input value={config.subjectAttribute ?? ""} onChange={(e) => set("subjectAttribute", e.target.value)} placeholder="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier" />
              </FormField></div>
            </Section>

            <Section title={t("connectionDetail.sectionResponseBindingTitle")} description={t("connectionDetail.sectionResponseBindingDesc")}>
              <FormField label={t("connectionDetail.fieldResponseBinding")}>
                <Select aria-label={t("connectionDetail.fieldResponseBinding")} value={config.responseBinding ?? "post"} onChange={(v) => set("responseBinding", v)} options={RESPONSE_BINDINGS} />
              </FormField>
              {(config.responseBinding ?? "post") === "artifact" ? (
                <>
                  <div className="hx-help">
                    <strong>{t("connectionDetail.classicDigidStrong")}</strong> {t("connectionDetail.classicDigidPart1")} <code>SAMLart</code> {t("connectionDetail.classicDigidPart2")}
                  </div>
                  <FormField label={t("connectionDetail.fieldArsUrl")} hint={t("connectionDetail.fieldArsUrlHint")}>
                    <Input value={config.artifactResolutionServiceUrl ?? ""} onChange={(e) => set("artifactResolutionServiceUrl", e.target.value)} placeholder="https://idp.example/saml/ars" />
                  </FormField>
                </>
              ) : (
                <div className="hx-help">
                  <strong>{t("connectionDetail.modernEidStrong")}</strong> {t("connectionDetail.modernEidPart1")} <code>SAMLResponse</code> {t("connectionDetail.modernEidPart2")}
                </div>
              )}
            </Section>
          </>
        )}
        {family === "eid" && tab === "connection" && (
          <Section title={t("connectionDetail.sectionBrokerEndpointsTitle")} description={t("connectionDetail.sectionBrokerEndpointsDesc")} layout="cols">
            <div className="hx-full"><FormField label={t("connectionDetail.fieldIdpEntityId")} required error={fieldErr("idpEntityId")}><Input value={config.idpEntityId ?? ""} onChange={(e) => set("idpEntityId", e.target.value)} placeholder="urn:nl-eid-gdi:…" /></FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldSsoUrl")} required error={fieldErr("ssoUrl")}><Input value={config.ssoUrl ?? ""} onChange={(e) => set("ssoUrl", e.target.value)} placeholder="https://broker.example/sso" /></FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldSpEntityId")} required error={fieldErr("spEntityId")} hint={t("connectionDetail.fieldSpEntityIdBrokerHint")}><Input value={config.spEntityId ?? ""} onChange={(e) => set("spEntityId", e.target.value)} /></FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldAcsUrl")}><Input value={config.assertionConsumerServiceUrl ?? ""} onChange={(e) => set("assertionConsumerServiceUrl", e.target.value)} /></FormField></div>
            <div className="hx-full"><FormField label={t("connectionDetail.fieldEidSloUrl")} hint={t("connectionDetail.fieldEidSloUrlHint")}>
              <Input value={config.singleLogoutServiceUrl ?? ""} onChange={(e) => set("singleLogoutServiceUrl", e.target.value)} placeholder="https://broker.example/slo" />
            </FormField></div>
          </Section>
        )}
        {family === "eid" && tab === "certs" && (
          <>
            <Section title={t("connectionDetail.sectionIdpCertTitle")} description={t("connectionDetail.sectionIdpCertEidDesc")}>
              <FormField label={t("connectionDetail.fieldIdpCertPem")}><Textarea className="hx-mono" value={config.idpSigningCertificate ?? ""} onChange={(e) => set("idpSigningCertificate", e.target.value)} rows={5} placeholder="-----BEGIN CERTIFICATE-----…" /></FormField>
            </Section>
            <Section title={t("connectionDetail.sectionSpKeysTitle")} description={t("connectionDetail.sectionSpKeysDesc")}>
              <FormField label={t("connectionDetail.fieldSpSignCert")}><Textarea className="hx-mono" value={config.spSigningCertificate ?? ""} onChange={(e) => set("spSigningCertificate", e.target.value)} rows={4} placeholder="-----BEGIN CERTIFICATE-----…" /></FormField>
              <FormField label={t("connectionDetail.fieldSpSignKey")} hint={t("connectionDetail.fieldSpSignKeyHint")}><Textarea className="hx-mono" value={config.spSigningPrivateKey ?? ""} onChange={(e) => set("spSigningPrivateKey", e.target.value)} rows={4} placeholder="-----BEGIN PRIVATE KEY-----…" /></FormField>
              <FormField label={t("connectionDetail.fieldSpDecryptKey")} hint={t("connectionDetail.fieldSpDecryptKeyHint")}><Textarea className="hx-mono" value={config.spDecryptionPrivateKey ?? ""} onChange={(e) => set("spDecryptionPrivateKey", e.target.value)} rows={4} placeholder="-----BEGIN PRIVATE KEY-----…" /></FormField>
            </Section>
          </>
        )}

        {/* ---- LDAP ---- */}
        {family === "ldap" && tab === "connection" && (
          <Section title={t("connectionDetail.sectionDirectoryTitle")} description={t("connectionDetail.sectionDirectoryDesc")} layout="cols">
            <div className="hx-full"><FormField label={t("connectionDetail.fieldConnUrl")} required error={fieldErr("url")}><Input value={config.url ?? ""} onChange={(e) => set("url", e.target.value)} placeholder="ldaps://dc.example.com:636" /></FormField></div>
            <FormField label={t("connectionDetail.fieldBindDn")} required error={fieldErr("bindDn")}><Input value={config.bindDn ?? ""} onChange={(e) => set("bindDn", e.target.value)} placeholder="cn=svc,ou=apps,dc=example,dc=com" /></FormField>
            <FormField label={t("connectionDetail.fieldBindPassword")} hint={t("connectionDetail.fieldBindPasswordHint")}><Input type="password" value={config.bindPassword ?? ""} onChange={(e) => set("bindPassword", e.target.value)} placeholder="••••••••" /></FormField>
          </Section>
        )}
        {family === "ldap" && tab === "search" && (
          <Section title={t("connectionDetail.sectionUserSearchTitle")} description={t("connectionDetail.sectionUserSearchDesc")} layout="cols">
            <FormField label={t("connectionDetail.fieldUserSearchBase")}><Input value={config.userSearchBase ?? ""} onChange={(e) => set("userSearchBase", e.target.value)} placeholder="ou=people,dc=example,dc=com" /></FormField>
            <FormField label={t("connectionDetail.fieldUserSearchFilter")} hint={t("connectionDetail.fieldUserSearchFilterHint")}><Input value={config.userSearchFilter ?? ""} onChange={(e) => set("userSearchFilter", e.target.value)} placeholder="(uid={0})" /></FormField>
            <FormField label={t("connectionDetail.fieldUidAttr")}><Input value={config.uidAttribute ?? ""} onChange={(e) => set("uidAttribute", e.target.value)} placeholder="uid" /></FormField>
            <FormField label={t("connectionDetail.fieldEmailAttr")}><Input value={config.emailAttribute ?? ""} onChange={(e) => set("emailAttribute", e.target.value)} placeholder="mail" /></FormField>
            <FormField label={t("connectionDetail.fieldFirstNameAttr")}><Input value={config.firstNameAttribute ?? ""} onChange={(e) => set("firstNameAttribute", e.target.value)} placeholder="givenName" /></FormField>
            <FormField label={t("connectionDetail.fieldLastNameAttr")}><Input value={config.lastNameAttribute ?? ""} onChange={(e) => set("lastNameAttribute", e.target.value)} placeholder="sn" /></FormField>
            <div className="hx-full">
              <div className="hx-formactions">
                <div>
                  <div className="hx-field__label">{t("connectionDetail.syncUsersLabel")}</div>
                  <div className="hx-help">{t("connectionDetail.syncUsersHint")}</div>
                </div>
                <Button variant="ghost" onClick={runSync} disabled={syncing}>{syncing ? t("connectionDetail.syncingLabel") : t("connectionDetail.syncUsersBtn")}</Button>
              </div>
            </div>
          </Section>
        )}

        {family === "oidc" && tab === "mappers" && (
          <Section title={t("connectionDetail.sectionAttrMappersTitle")} description={t("connectionDetail.sectionAttrMappersDesc")}>
            <MapperEditor mappers={mappers} setMappers={setMappers} placeholderSource="given_name" />
          </Section>
        )}
      </PageBody>

      <ConfirmDialog open={confirmDel} title={t("connectionDetail.confirmDeleteTitle")}
        message={t("connectionDetail.confirmDeleteMsg", { name: displayName || alias })}
        onConfirm={remove} onCancel={() => setConfirmDel(false)} />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

function MapperEditor({ mappers, setMappers, placeholderSource = "department" }: {
  mappers: AttributeMapper[]; setMappers: React.Dispatch<React.SetStateAction<AttributeMapper[]>>; placeholderSource?: string;
}) {
  const { t } = useT();
  const edit = (i: number, patch: Partial<AttributeMapper>) => setMappers((rows) => rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const add = () => setMappers((rows) => [...rows, { source: "", target: "" }]);
  const removeRow = (i: number) => setMappers((rows) => rows.filter((_, j) => j !== i));
  return (
    <div className="hx-colstack">
      {mappers.map((m, i) => (
        <div key={i} className="hx-inputrow">
          <Input value={m.source} onChange={(e) => edit(i, { source: e.target.value })} aria-label={t("connectionDetail.mapperSourceAriaLabel", { n: i + 1 })} placeholder={t("connectionDetail.mapperSourcePlaceholder", { example: placeholderSource })} />
          <span aria-hidden="true" className="hx-faint">→</span>
          <Input value={m.target} onChange={(e) => edit(i, { target: e.target.value })} aria-label={t("connectionDetail.mapperTargetAriaLabel", { n: i + 1 })} placeholder={t("connectionDetail.mapperTargetPlaceholder")} />
          <button type="button" className="hx-ghosticon hx-ghosticon--36" aria-label={t("connectionDetail.mapperRemoveAriaLabel", { n: i + 1 })} onClick={() => removeRow(i)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
          </button>
        </div>
      ))}
      <div><Button variant="ghost" onClick={add}>{t("connectionDetail.mapperAddBtn")}</Button></div>
    </div>
  );
}
