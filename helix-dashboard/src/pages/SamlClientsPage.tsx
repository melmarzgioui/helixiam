/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { CopyRow } from "../components/CopyRow";
import { fetchOidcEndpoints } from "../api/endpoints";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Alert } from "../components/Alert";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { FormField, Input, Textarea, Select } from "../components/FormField";
import { RowMenu } from "../components/RowMenu";
import { Checkbox } from "../components/Choice";
import { Tabs } from "../components/Tabs";
import { SamlClientApi, SamlClient, SamlClientWrite, SamlSpOptions, validateSamlClient, samlIdpMetadataUrl } from "../api/samlClients";
import { useT } from "../i18n/LocaleContext";

export interface SamlClientsPageProps {
  api: SamlClientApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

const DEFAULT_AUTHN_CTX = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

/** SAML relying parties (service providers) that trust this realm as their SAML 2.0 IdP. */
export function SamlClientsPage({ api, realmId }: SamlClientsPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<SamlClient[] | null>(null);
  const [editing, setEditing] = React.useState<SamlClient | "new" | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);
  const [toDelete, setToDelete] = React.useState<SamlClient | null>(null);

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => {
      setRows([]);
      setNote({ tone: "error", title: t("samlClients.loadError"), message: String(e.message ?? e) });
    });
  }, [api, realmId, t]);
  React.useEffect(reload, [reload]);

  const save = async (write: SamlClientWrite, isNew: boolean) => {
    setBusy(true);
    try {
      if (isNew) await api.create(realmId, write);
      else await api.update(realmId, write.entityId, write);
      setEditing(null);
      setNote({ tone: "success", title: isNew ? t("samlClients.registeredSuccess") : t("samlClients.updatedSuccess"), message: t("samlClients.savedMsg", { entityId: write.entityId, realm: realmId }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("samlClients.saveError"), message: String((e as Error).message ?? e) });
    } finally { setBusy(false); }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const rp = toDelete;
    setToDelete(null);
    try {
      await api.remove(realmId, rp.entityId);
      setNote({ tone: "success", title: t("samlClients.deleteSuccess"), message: rp.entityId });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("samlClients.deleteError"), message: String((e as Error).message ?? e) });
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("samlClients.title")}
        description={<>{t("samlClients.descriptionPrefix")} <strong>{realmId}</strong> {t("samlClients.descriptionSuffix")}</>}
        actions={<Button variant="primary" onClick={() => setEditing("new")}>{t("samlClients.registerRp")}</Button>}
      />

      <PageBody>
        {rows === null ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("samlClients.loading")} /></div>
        ) : rows.length === 0 ? (
          <EmptyState title={t("samlClients.emptyTitle")} message={t("samlClients.emptyMessage")}
            action={<Button variant="primary" onClick={() => setEditing("new")}>{t("samlClients.registerRp")}</Button>} />
        ) : (
          <>
            {/* desktop table */}
            <div className="hx-card hx-show-desktop">
              <div className="hx-tablescroll">
                <table className="hx-table">
                  <thead>
                    <tr><th>{t("samlClients.colEntityId")}</th><th>{t("samlClients.colAcsUrl")}</th><th>{t("samlClients.colSlo")}</th><th>{t("samlClients.colStatus")}</th><th className="hx-col-actions" aria-label="Actions" /></tr>
                  </thead>
                  <tbody>
                    {rows.map((rp) => (
                      <tr key={rp.entityId} onClick={() => setEditing(rp)} className="hx-row-clickable">
                        <td><strong>{rp.entityId}</strong></td>
                        <td className="hx-muted hx-mono">{rp.assertionConsumerServiceUrl}</td>
                        <td>{rp.singleLogoutServiceUrl ? <Badge tone="neutral">{t("samlClients.sloLabel")}</Badge> : <span className="hx-faint">—</span>}</td>
                        <td><Badge tone={rp.enabled ? "accent" : "neutral"}>{rp.enabled ? t("samlClients.enabled") : t("samlClients.disabled")}</Badge></td>
                        <td className="hx-cell-right" onClick={(e) => e.stopPropagation()}>
                          <RowMenu items={[
                            { label: t("common.edit"), onSelect: () => setEditing(rp) },
                            { label: t("common.delete"), danger: true, onSelect: () => setToDelete(rp) },
                          ]} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* mobile cards */}
            <div className="hx-cards hx-show-mobile">
              {rows.map((rp) => (
                <div className="hx-rowcard hx-rowcard--clickable" key={rp.entityId} onClick={() => setEditing(rp)}>
                  <div className="hx-rowcard__head">
                    <div className="hx-rowcard__grow">
                      <div className="hx-rowcard__title">{rp.entityId}</div>
                    </div>
                    <Badge tone={rp.enabled ? "accent" : "neutral"}>{rp.enabled ? t("samlClients.enabled") : t("samlClients.disabled")}</Badge>
                  </div>
                  <div className="hx-rowcard__fields">
                    <div className="hx-rowcard__field">
                      <span className="hx-rowcard__label">{t("samlClients.colAcsUrl")}</span>
                      <span className="hx-rowcard__value hx-muted hx-mono">{rp.assertionConsumerServiceUrl}</span>
                    </div>
                    <div className="hx-rowcard__field">
                      <span className="hx-rowcard__label">{t("samlClients.colSlo")}</span>
                      <span className="hx-rowcard__value">
                        {rp.singleLogoutServiceUrl ? <Badge tone="neutral">{t("samlClients.sloLabel")}</Badge> : <span className="hx-faint">—</span>}
                      </span>
                    </div>
                  </div>
                  <div className="hx-rowcard__actions" onClick={(e) => e.stopPropagation()}>
                    <Button variant="ghost" onClick={() => setEditing(rp)}>{t("common.edit")}</Button>
                    <Button variant="ghost" onClick={() => setToDelete(rp)}>{t("common.delete")}</Button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </PageBody>

      <Modal open={editing !== null} title={editing === "new" ? t("samlClients.registerModalTitle") : t("samlClients.editModalTitle")} onClose={() => setEditing(null)} width={760}>
        {busy ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("samlClients.saving")} /></div>
        ) : editing && (
          <SamlClientForm
            initial={editing === "new" ? null : editing}
            onSubmit={(w) => save(w, editing === "new")}
            onCancel={() => setEditing(null)}
            samlApi={api}
            realmId={realmId}
            apiBase={import.meta.env?.VITE_API_BASE ?? ""}
          />
        )}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("samlClients.deleteTitle")}
        message={t("samlClients.deleteMessage", { entityId: toDelete?.entityId ?? "" })}
        onConfirm={confirmDelete}
        onCancel={() => setToDelete(null)}
      />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

const NAME_ID_FORMATS = [
  { value: "", label: "IdP default (persistent)" },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", label: "Persistent" },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", label: "Transient" },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", label: "Email address" },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", label: "Unspecified" },
];
const SIG_ALGOS = [
  { value: "", label: "RSA-SHA256 (default)" },
  { value: "RSA_SHA256", label: "RSA-SHA256" },
  { value: "RSA_SHA512", label: "RSA-SHA512" },
  { value: "RSA_SHA1", label: "RSA-SHA1 (legacy)" },
];
const DIGEST_ALGOS = [
  { value: "", label: "SHA-256 (default)" },
  { value: "SHA256", label: "SHA-256" },
  { value: "SHA512", label: "SHA-512" },
  { value: "SHA1", label: "SHA-1 (legacy)" },
];

/** Split a multi-line textarea value into a trimmed, de-blanked list. */
const linesToList = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);

/** Which form tab surfaces a given validation error, so a failed submit can jump to it. */
const ERROR_TAB: Record<string, string> = {
  entityId: "settings",
  assertionConsumerServiceUrl: "settings",
  singleLogoutServiceUrl: "settings",
  additionalAcsUrls: "settings",
  encryptionCertificate: "signing",
  extraRecipients: "audience",
};

/** Create/edit form. EntityID is immutable once registered (it keys the relying party). */
export function SamlClientForm({ initial, onSubmit, onCancel, samlApi, realmId, apiBase }: {
  initial: SamlClient | null;
  onSubmit: (w: SamlClientWrite) => void;
  onCancel: () => void;
  /** When provided, enables WSO2-class SP metadata import + the realm descriptor link. */
  samlApi?: SamlClientApi;
  realmId?: string;
  apiBase?: string;
}) {
  const { t } = useT();
  const isNew = initial === null;
  const o0 = initial?.options ?? {};
  const [tab, setTab] = React.useState("settings");
  const [entityId, setEntityId] = React.useState(initial?.entityId ?? "");
  const [acs, setAcs] = React.useState(initial?.assertionConsumerServiceUrl ?? "");
  const [slo, setSlo] = React.useState(initial?.singleLogoutServiceUrl ?? "");
  const [authnCtx, setAuthnCtx] = React.useState(initial?.defaultAuthnContextClassRef ?? DEFAULT_AUTHN_CTX);
  const [cert, setCert] = React.useState(initial?.signingCertificate ?? "");
  const [enabled, setEnabled] = React.useState(initial?.enabled ?? true);
  const [attempted, setAttempted] = React.useState(false);

  // WSO2-class advanced options. Booleans whose IdP default is "on" (sign assertion, sign logout,
  // include attributes) default to true; the rest default to off.
  const [signAssertion, setSignAssertion] = React.useState(o0.signAssertion ?? true);
  const [signResponse, setSignResponse] = React.useState(o0.signResponse ?? false);
  const [wantAuthnSigned, setWantAuthnSigned] = React.useState(o0.wantAuthnRequestsSigned ?? false);
  const [wantLogoutSigned, setWantLogoutSigned] = React.useState(o0.wantLogoutRequestsSigned ?? true);
  const [encryptAssertion, setEncryptAssertion] = React.useState(o0.encryptAssertion ?? false);
  const [encCert, setEncCert] = React.useState(o0.encryptionCertificate ?? "");
  const [sigAlgo, setSigAlgo] = React.useState(o0.signatureAlgorithm ?? "");
  const [digestAlgo, setDigestAlgo] = React.useState(o0.digestAlgorithm ?? "");
  const [nameIdFormat, setNameIdFormat] = React.useState(o0.nameIdFormat ?? "");
  const [includeAttributes, setIncludeAttributes] = React.useState(o0.includeAttributes ?? true);
  const [addAcs, setAddAcs] = React.useState((o0.additionalAcsUrls ?? []).join("\n"));
  const [extraAud, setExtraAud] = React.useState((o0.extraAudiences ?? []).join("\n"));
  const [extraRcpt, setExtraRcpt] = React.useState((o0.extraRecipients ?? []).join("\n"));
  const [lifetime, setLifetime] = React.useState(o0.assertionLifetimeSeconds ? String(o0.assertionLifetimeSeconds) : "");
  const [idpInitiated, setIdpInitiated] = React.useState(o0.idpInitiatedSsoEnabled ?? false);
  const [backChannelSlo, setBackChannelSlo] = React.useState(o0.backChannelSloEnabled ?? false);
  const [metaXml, setMetaXml] = React.useState("");
  const [metaUrl, setMetaUrl] = React.useState("");
  const [importErr, setImportErr] = React.useState<string | null>(null);
  const [importMsg, setImportMsg] = React.useState<string | null>(null);
  const [importing, setImporting] = React.useState(false);

  // Translated option lists (computed inside the component so t() is available)
  const nameIdOptions = [
    { value: "", label: t("samlClients.nameIdDefault") },
    { value: NAME_ID_FORMATS[1].value, label: t("samlClients.nameIdPersistent") },
    { value: NAME_ID_FORMATS[2].value, label: t("samlClients.nameIdTransient") },
    { value: NAME_ID_FORMATS[3].value, label: t("samlClients.nameIdEmail") },
    { value: NAME_ID_FORMATS[4].value, label: t("samlClients.nameIdUnspecified") },
  ];
  const sigAlgoOptions = [
    { value: "", label: t("samlClients.sigAlgoDefault") },
    { value: SIG_ALGOS[1].value, label: SIG_ALGOS[1].label },
    { value: SIG_ALGOS[2].value, label: SIG_ALGOS[2].label },
    { value: SIG_ALGOS[3].value, label: t("samlClients.sigAlgoLegacy1") },
  ];
  const digestAlgoOptions = [
    { value: "", label: t("samlClients.digestAlgoDefault") },
    { value: DIGEST_ALGOS[1].value, label: DIGEST_ALGOS[1].label },
    { value: DIGEST_ALGOS[2].value, label: DIGEST_ALGOS[2].label },
    { value: DIGEST_ALGOS[3].value, label: t("samlClients.digestAlgoLegacy1") },
  ];

  const options: SamlSpOptions = {
    signAssertion,
    signResponse,
    wantAuthnRequestsSigned: wantAuthnSigned,
    wantLogoutRequestsSigned: wantLogoutSigned,
    encryptAssertion,
    encryptionCertificate: encCert.trim() || null,
    signatureAlgorithm: sigAlgo || null,
    digestAlgorithm: digestAlgo || null,
    nameIdFormat: nameIdFormat || null,
    includeAttributes,
    additionalAcsUrls: linesToList(addAcs),
    extraAudiences: linesToList(extraAud),
    extraRecipients: linesToList(extraRcpt),
    assertionLifetimeSeconds: lifetime.trim() ? Number(lifetime.trim()) : null,
    idpInitiatedSsoEnabled: idpInitiated,
    backChannelSloEnabled: backChannelSlo,
  };

  const write: SamlClientWrite = {
    entityId: entityId.trim(),
    assertionConsumerServiceUrl: acs.trim(),
    singleLogoutServiceUrl: slo.trim() || null,
    defaultAuthnContextClassRef: authnCtx.trim() || null,
    signingCertificate: cert.trim() || null,
    enabled,
    options,
  };
  const errors = validateSamlClient(write);

  const submit = () => {
    setAttempted(true);
    const keys = Object.keys(errors);
    if (keys.length > 0) {
      // Jump to the tab that surfaces the first error so it's never hidden behind another tab.
      setTab(ERROR_TAB[keys[0]] ?? "settings");
      return;
    }
    onSubmit(write);
  };

  /** Apply a parsed SP metadata result to the form fields and report what was filled. */
  const applyImported = (w: SamlClientWrite) => {
    const filled: string[] = [];
    if (w.entityId) { setEntityId(w.entityId); filled.push("entity ID"); }
    if (w.assertionConsumerServiceUrl) { setAcs(w.assertionConsumerServiceUrl); filled.push("ACS"); }
    if (w.singleLogoutServiceUrl) { setSlo(w.singleLogoutServiceUrl); filled.push("SLO"); }
    if (w.signingCertificate) { setCert(w.signingCertificate); filled.push("certificate"); }
    if (w.options?.nameIdFormat) { setNameIdFormat(w.options.nameIdFormat); filled.push("NameID format"); }
    if (w.options?.additionalAcsUrls?.length) { setAddAcs(w.options.additionalAcsUrls.join("\n")); filled.push("extra ACS URLs"); }
    setImportMsg(t("samlClients.importedFields", { fields: filled.length ? filled.join(", ") : t("samlClients.availableFields") }));
  };

  const doImport = async () => {
    if (!samlApi || !realmId) return;
    setImportErr(null); setImportMsg(null);
    if (!metaXml.trim()) { setImportErr(t("samlClients.pasteXmlFirst")); return; }
    setImporting(true);
    try {
      applyImported(await samlApi.importMetadata(realmId, metaXml.trim()));
      setMetaXml("");
    } catch (e: unknown) {
      setImportErr(String((e as Error).message ?? e));
    } finally { setImporting(false); }
  };

  const doImportUrl = async () => {
    if (!samlApi || !realmId) return;
    setImportErr(null); setImportMsg(null);
    const u = metaUrl.trim();
    if (!u) { setImportErr(t("samlClients.enterUrlFirst")); return; }
    if (!/^https?:\/\//i.test(u)) { setImportErr(t("samlClients.urlMustStart")); return; }
    setImporting(true);
    try {
      applyImported(await samlApi.importMetadataUrl(realmId, u));
      setMetaUrl("");
    } catch (e: unknown) {
      setImportErr(String((e as Error).message ?? e));
    } finally { setImporting(false); }
  };

  // The descriptor is served by the auth server (the OIDC issuer host), NOT the dashboard. Derive its URL
  // from the realm's discovery endpoint so it shares the exact host + realm path the SP already uses for
  // OIDC; fall back to apiBase / the browser origin only if discovery can't be fetched.
  const [descriptorUrl, setDescriptorUrl] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!realmId) { setDescriptorUrl(null); return; }
    const fallback = samlIdpMetadataUrl((apiBase && apiBase.trim()) ? apiBase : (typeof window !== "undefined" ? window.location.origin : ""), realmId);
    let alive = true;
    fetchOidcEndpoints(realmId, apiBase ?? "")
      .then((e) => { if (alive) setDescriptorUrl(e.discovery.replace(/\/\.well-known\/openid-configuration$/, "/saml/idp/metadata")); })
      .catch(() => { if (alive) setDescriptorUrl(fallback); });
    return () => { alive = false; };
  }, [realmId, apiBase]);

  const metadataEnabled = !!(samlApi && realmId);
  const TABS = [
    { id: "settings", label: t("samlClients.tabSettings") },
    { id: "signing", label: t("samlClients.tabSigning") },
    { id: "nameid", label: t("samlClients.tabNameId") },
    { id: "audience", label: t("samlClients.tabAudience") },
    ...(metadataEnabled ? [{ id: "metadata", label: t("samlClients.tabMetadata") }] : []),
  ];

  return (
    <div>
      <Tabs tabs={TABS} value={tab} onChange={setTab} />

      <div className="hx-tabpanel">
        {tab === "settings" && (
          <div className="hx-clientgrid">
            <Section title={t("samlClients.spTitle")} description={t("samlClients.spDesc")}>
              <FormField label={t("samlClients.entityIdLabel")} required error={attempted ? errors.entityId : undefined}
                hint={t("samlClients.entityIdHint")}>
                <Input value={entityId} onChange={(e) => setEntityId(e.target.value)} placeholder="helix-sandbox-sp" autoFocus disabled={!isNew} />
              </FormField>
              <FormField label={t("samlClients.acsLabel")} required error={attempted ? errors.assertionConsumerServiceUrl : undefined}
                hint={t("samlClients.acsHint")}>
                <Input value={acs} onChange={(e) => setAcs(e.target.value)} placeholder="https://app.example.com/saml/acs" />
              </FormField>
              <FormField label={t("samlClients.additionalAcsLabel")} error={attempted ? errors.additionalAcsUrls : undefined}
                hint={t("samlClients.additionalAcsHint")}>
                <Textarea className="hx-mono" value={addAcs} onChange={(e) => setAddAcs(e.target.value)} rows={2} placeholder="https://app.example.com/saml/acs2" />
              </FormField>
              <FormField label={t("samlClients.sloLabel2")} error={attempted ? errors.singleLogoutServiceUrl : undefined}
                hint={t("samlClients.sloHint")}>
                <Input value={slo} onChange={(e) => setSlo(e.target.value)} placeholder="https://app.example.com/saml/slo" />
              </FormField>
            </Section>

            <Section title={t("samlClients.assuranceTitle")} description={t("samlClients.assuranceDesc")}>
              <FormField label={t("samlClients.authnCtxLabel")} hint={t("samlClients.authnCtxHint")}>
                <Input value={authnCtx} onChange={(e) => setAuthnCtx(e.target.value)} />
              </FormField>
              <Checkbox label={t("samlClients.enabledCheckbox")} checked={enabled} onChange={setEnabled} />
            </Section>
          </div>
        )}

        {tab === "signing" && (
          <div className="hx-clientgrid">
            <Section title={t("samlClients.signingTitle")} description={t("samlClients.signingDesc")}>
              <div className="hx-clientgrid">
                <Checkbox label={t("samlClients.signAssertion")} checked={signAssertion} onChange={setSignAssertion} />
                <Checkbox label={t("samlClients.signResponse")} checked={signResponse} onChange={setSignResponse} />
                <Checkbox label={t("samlClients.wantAuthnSigned")} checked={wantAuthnSigned} onChange={setWantAuthnSigned} />
                <Checkbox label={t("samlClients.wantLogoutSigned")} checked={wantLogoutSigned} onChange={setWantLogoutSigned} />
              </div>
              <p className="hx-help">
                {t("samlClients.signingNote")}
              </p>
            </Section>

            <Section title={t("samlClients.algorithmsTitle")} description={t("samlClients.algorithmsDesc")} layout="cols">
              <FormField label={t("samlClients.sigAlgoLabel")} hint={t("samlClients.sigAlgoHint")}>
                <Select aria-label={t("samlClients.sigAlgoLabel")} value={sigAlgo} onChange={setSigAlgo} options={sigAlgoOptions} />
              </FormField>
              <FormField label={t("samlClients.digestAlgoLabel")} hint={t("samlClients.digestAlgoHint")}>
                <Select aria-label={t("samlClients.digestAlgoLabel")} value={digestAlgo} onChange={setDigestAlgo} options={digestAlgoOptions} />
              </FormField>
            </Section>

            <Section title={t("samlClients.spCertTitle")} description={t("samlClients.spCertDesc")}>
              <FormField label={t("samlClients.certLabel")} hint={t("samlClients.certHint")}>
                <Textarea className="hx-mono" value={cert} onChange={(e) => setCert(e.target.value)} rows={4} placeholder="-----BEGIN CERTIFICATE-----…" />
              </FormField>
            </Section>

            <Section title={t("samlClients.encryptionTitle")} description={t("samlClients.encryptionDesc")}>
              <div className="hx-clientgrid">
                <Checkbox label={t("samlClients.encryptAssertion")} checked={encryptAssertion} onChange={setEncryptAssertion} />
                {encryptAssertion && (
                  <FormField label={t("samlClients.encCertLabel")} error={attempted ? errors.encryptionCertificate : undefined}
                    hint={t("samlClients.encCertHint")}>
                    <Textarea className="hx-mono" value={encCert} onChange={(e) => setEncCert(e.target.value)} rows={4} placeholder="-----BEGIN CERTIFICATE-----…" />
                  </FormField>
                )}
              </div>
            </Section>
          </div>
        )}

        {tab === "nameid" && (
          <div className="hx-clientgrid">
            <Section title={t("samlClients.nameIdTitle")} description={t("samlClients.nameIdDesc")}>
              <FormField label={t("samlClients.nameIdFormat")} hint={t("samlClients.nameIdHint")}>
                <Select aria-label={t("samlClients.nameIdFormat")} value={nameIdFormat} onChange={setNameIdFormat} options={nameIdOptions} />
              </FormField>
            </Section>

            <Section title={t("samlClients.attributesTitle")} description={t("samlClients.attributesDesc")}>
              <Checkbox label={t("samlClients.includeAttributes")} checked={includeAttributes} onChange={setIncludeAttributes} />
              <p className="hx-help">
                {t("samlClients.attributesNote")}
              </p>
            </Section>
          </div>
        )}

        {tab === "audience" && (
          <div className="hx-clientgrid">
            <Section title={t("samlClients.audienceTitle")} description={t("samlClients.audienceDesc")}>
              <FormField label={t("samlClients.extraAudLabel")} hint={t("samlClients.extraAudHint")}>
                <Textarea className="hx-mono" value={extraAud} onChange={(e) => setExtraAud(e.target.value)} rows={2} placeholder="urn:app:another-audience" />
              </FormField>
              <FormField label={t("samlClients.extraRcptLabel")} error={attempted ? errors.extraRecipients : undefined}
                hint={t("samlClients.extraRcptHint")}>
                <Textarea className="hx-mono" value={extraRcpt} onChange={(e) => setExtraRcpt(e.target.value)} rows={2} placeholder="https://app.example.com/saml/acs" />
              </FormField>
            </Section>

            <Section title={t("samlClients.sloSsoTitle")} description={t("samlClients.sloSsoDesc")}>
              <div className="hx-clientgrid">
                <Checkbox label={t("samlClients.idpInitiated")} checked={idpInitiated} onChange={setIdpInitiated} />
                <Checkbox label={t("samlClients.backChannelSlo")} checked={backChannelSlo} onChange={setBackChannelSlo} />
              </div>
            </Section>

            <Section title={t("samlClients.lifetimeTitle")} description={t("samlClients.lifetimeDesc")} layout="cols">
              <FormField label={t("samlClients.lifetimeLabel")} hint={t("samlClients.lifetimeHint")}>
                <Input value={lifetime} onChange={(e) => setLifetime(e.target.value.replace(/[^0-9]/g, ""))} placeholder="300" inputMode="numeric" />
              </FormField>
            </Section>
          </div>
        )}

        {tab === "metadata" && metadataEnabled && (
          <div className="hx-clientgrid">
            <Section title={t("samlClients.realmMetadataTitle")} description={t("samlClients.realmMetadataDesc")}>
              {descriptorUrl ? (
                <CopyRow label={t("samlClients.metadataUrlLabel")} value={descriptorUrl} />
              ) : (
                <p className="hx-help">{t("samlClients.resolvingUrl")}</p>
              )}
            </Section>

            <Section title={t("samlClients.importTitle")} description={t("samlClients.importDesc")}>
              <FormField label={t("samlClients.fromUrlLabel")} hint={t("samlClients.fromUrlHint")}>
                <div className="hx-inputrow">
                  <Input value={metaUrl} onChange={(e) => setMetaUrl(e.target.value)} placeholder="https://sp.example.com/saml/metadata" aria-label={t("samlClients.fromUrlLabel")} />
                  <Button variant="ghost" onClick={doImportUrl} disabled={importing}>{importing ? t("samlClients.importing") : t("samlClients.importFromUrl")}</Button>
                </div>
              </FormField>
              <FormField label={t("samlClients.pasteXmlLabel")} hint={t("samlClients.pasteXmlHint")}>
                <Textarea className="hx-mono" value={metaXml} onChange={(e) => setMetaXml(e.target.value)} rows={4} placeholder="<md:EntityDescriptor …>" />
              </FormField>
              <div><Button variant="ghost" onClick={doImport} disabled={importing}>{importing ? t("samlClients.importing") : t("samlClients.importAndPrefill")}</Button></div>
              {importErr && <Alert tone="danger">{importErr}</Alert>}
              {importMsg && <Alert tone="success">{importMsg}</Alert>}
            </Section>
          </div>
        )}
      </div>

      {attempted && Object.keys(errors).length > 0 && (
        <Alert tone="danger">{t("samlClients.validationError")}</Alert>
      )}
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={submit}>{isNew ? t("samlClients.registerRp") : t("samlClients.saveChanges")}</Button>
      </div>
    </div>
  );
}
