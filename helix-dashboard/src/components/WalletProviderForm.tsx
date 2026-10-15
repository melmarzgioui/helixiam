/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Section } from "./Page";
import { Alert } from "./Alert";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { Checkbox, RadioCard } from "./Choice";
import { Detail, DetailList } from "./DetailList";
import { FormField, Input, Textarea } from "./FormField";
import { Select } from "./Select";
import { Switch } from "./Switch";
import { SecretInput } from "./SecretInput";
import { useT } from "../i18n/LocaleContext";
import { absoluteTime } from "../api/datetime";
import { AdminApiError } from "../api/adminError";
import type { CertificateInfo, VerifierKey, WalletAdminApi, WalletMetadata } from "../api/wallet";
import {
  LOA_LADDER, MDOC_FORMAT, SD_JWT_FORMAT, TTL_RANGE, commonName, expiryState, parseHostList, parseOriginList, sanCheck,
  trustedAuthoritiesEffective, validateKeyImport, walletWarnings, type KeyImportForm, type WalletForm,
  type WalletValidationContext,
} from "../pages/walletProvider";

// The EUDI Wallet (OpenID4VP) provider form, shared by the "Add identity provider" wizard (one group per step) and
// the connection detail page (one group per tab). State and rules live in pages/walletProvider.ts; these components
// only render them. Errors are i18n keys from validateWallet, or server messages from a 400 (t() returns those as is).

/** The dev-only raw private key (accessCertificatePrivateKey), a write-only secret. */
export interface WalletDevKey {
  stored: boolean;
  value: string;
  replacing: boolean;
  clearing: boolean;
  onChange: (value: string) => void;
  onReplace: (on: boolean) => void;
  onClear: (on: boolean) => void;
}

export interface WalletSectionProps {
  realmId: string;
  api: WalletAdminApi;
  form: WalletForm;
  onChange: (patch: Partial<WalletForm>) => void;
  /** Field → message (shown as is through t()). Pass only once the admin tried to continue or save. */
  errors: Record<string, string>;
  meta: WalletMetadata;
  keys: VerifierKey[];
  onKeyImported: (key: VerifierKey) => void;
  /** The stored form of an existing provider (drives the place-of-birth warning); null for a new one. */
  original?: WalletForm | null;
  devKey: WalletDevKey;
}

/** Loads what the wallet form needs from the server: the metadata (claim catalogue, dev profile) and the realm's keys. */
export function useWalletData(api: WalletAdminApi | undefined, realmId: string | undefined, enabled = true) {
  const [meta, setMeta] = React.useState<WalletMetadata | null>(null);
  const [keys, setKeys] = React.useState<VerifierKey[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!enabled || !api || !realmId) return;
    let live = true;
    setError(null);
    Promise.all([api.metadata(realmId), api.listKeys(realmId)])
      .then(([m, k]) => { if (live) { setMeta(m); setKeys(k); } })
      .catch((e: unknown) => { if (live) setError(String((e as Error).message ?? e)); });
    return () => { live = false; };
  }, [api, realmId, enabled]);
  const addKey = React.useCallback((k: VerifierKey) => setKeys((ks) => [...(ks ?? []).filter((x) => x.keyRef !== k.keyRef), k]), []);
  return { meta, keys, error, addKey };
}

/** The validation context for a form: the server profile, the claim catalogue, the chosen key's SANs, the dev key. */
export function walletContext(form: WalletForm, meta: WalletMetadata | null, keys: VerifierKey[] | null,
  devKey?: Pick<WalletDevKey, "stored" | "value" | "clearing">): WalletValidationContext {
  const key = keys?.find((k) => k.keyRef === form.accessKeyRef.trim());
  return {
    devProfile: !!meta?.devProfile,
    pidClaims: meta?.pidClaims,
    keyDnsNames: key ? key.certificate.dnsNames : undefined,
    devKey: devKey ? { stored: devKey.stored, pending: !!devKey.value.trim(), clearing: devKey.clearing } : undefined,
  };
}

function useFieldError(errors: Record<string, string>) {
  const { t } = useT();
  return (field: string) => (errors[field] ? t(errors[field]) : undefined);
}

/** Reads a chosen text file (PEM) into a field. Renders as a ghost button. */
function FileButton({ label, onText }: { label: string; onText: (text: string) => void }) {
  const id = React.useId();
  return (
    <label className="hx-btn hx-btn--ghost hx-filebtn" htmlFor={id}>
      {label}
      <input id={id} type="file" className="hx-visually-hidden" accept=".pem,.crt,.cer,.key,.txt,text/plain,application/x-pem-file"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = "";
          if (file) void file.text().then(onText);
        }} />
    </label>
  );
}

function ExpiryBadge({ notAfter }: { notAfter: string }) {
  const { t } = useT();
  const state = expiryState(notAfter);
  return state === "expired" ? <Badge tone="danger">{t("wallet.key.expired")}</Badge>
    : state === "soon" ? <Badge tone="warning">{t("wallet.key.expiresSoon")}</Badge>
      : <Badge tone="success">{t("wallet.key.valid")}</Badge>;
}

// ---------------------------------------------------------------------------------------------------- access key

export function WalletAccessSection(props: WalletSectionProps) {
  const { realmId, api, form, onChange, errors, meta, keys, onKeyImported, devKey } = props;
  const { t, locale } = useT();
  const fe = useFieldError(errors);
  const [importing, setImporting] = React.useState(false);
  const [imported, setImported] = React.useState<string | null>(null);
  const ref = form.accessKeyRef.trim();
  const key = keys.find((k) => k.keyRef === ref);
  const unknownRef = !!ref && !key;
  const options = [
    ...keys.map((k) => ({
      value: k.keyRef,
      label: k.name,
      description: `${commonName(k.certificate.subject)} · ${t("wallet.key.validUntil")} ${absoluteTime(k.certificate.notAfter, locale)}`,
    })),
    ...(unknownRef ? [{ value: ref, label: ref.slice(ref.lastIndexOf("/") + 1) || ref, description: t("wallet.access.unknownRef") }] : []),
  ];
  const san = sanCheck(form.clientIdHost, key?.certificate.dnsNames);
  const showDev = meta.devProfile || devKey.stored;

  return (
    <>
      <Section title={t("wallet.access.title")} description={t("wallet.access.desc")}
        actions={!importing && <Button variant="ghost" onClick={() => { setImporting(true); setImported(null); }}>{t("wallet.access.import")}</Button>}>
        {imported && <Alert tone="success" title={t("wallet.import.done")} onDismiss={() => setImported(null)}>{t("wallet.import.doneMsg", { name: imported })}</Alert>}
        {keys.length === 0 && !importing && <Alert tone="info">{t("wallet.access.noKeys")}</Alert>}
        {importing && (
          <KeyImportPanel realmId={realmId} api={api} onCancel={() => setImporting(false)}
            onImported={(k) => { onKeyImported(k); onChange({ accessKeyRef: k.keyRef }); setImporting(false); setImported(k.name); }} />
        )}
        <FormField label={t("wallet.access.key")} required={!devKey.stored} error={fe("accessKeyRef")} hint={t("wallet.access.keyHint")}>
          <Select aria-label={t("wallet.access.key")} value={ref} placeholder={t("wallet.access.keyPlaceholder")}
            onChange={(v) => onChange({ accessKeyRef: v })} options={options} />
        </FormField>
        {unknownRef && <Alert tone="warning">{t("wallet.access.unknownRef")}</Alert>}
        {key && (
          <DetailList>
            <Detail label={t("wallet.key.subject")} sub={key.certificate.subject}>{commonName(key.certificate.subject)}</Detail>
            <Detail label={t("wallet.key.issuer")} sub={key.certificate.issuer}>{commonName(key.certificate.issuer)}</Detail>
            <Detail label={t("wallet.key.validUntil")} center>
              <span className="hx-badges">{absoluteTime(key.certificate.notAfter, locale)} <ExpiryBadge notAfter={key.certificate.notAfter} /></span>
            </Detail>
            <Detail label={t("wallet.key.algorithm")}>{`${key.algorithm} · ${key.certificate.keyAlgorithm}`}</Detail>
            <Detail label={t("wallet.key.dnsNames")}>{key.certificate.dnsNames.join(", ") || t("wallet.key.noDnsNames")}</Detail>
            <Detail label={t("wallet.key.ref")} sub={key.createdAt ? `${t("wallet.key.imported")} ${absoluteTime(key.createdAt, locale)}` : undefined} mono={key.keyRef} />
          </DetailList>
        )}
      </Section>

      <Section title={t("wallet.clientId.title")} description={t("wallet.clientId.desc")}>
        <FormField label={t("wallet.clientId.scheme")} group="radiogroup">
          <div className="hx-choicegrid">
            <RadioCard roving selected={form.clientIdScheme === "x509_hash"} onSelect={() => onChange({ clientIdScheme: "x509_hash" })}
              title={t("wallet.clientId.hash")} description={t("wallet.clientId.hashDesc")} />
            <RadioCard roving selected={form.clientIdScheme === "x509_san_dns"} onSelect={() => onChange({ clientIdScheme: "x509_san_dns" })}
              title={t("wallet.clientId.sanDns")} description={t("wallet.clientId.sanDnsDesc")} />
          </div>
        </FormField>
        {form.clientIdScheme === "x509_san_dns" && (
          <>
            <FormField label={t("wallet.clientId.host")} required error={fe("clientIdHost")} hint={t("wallet.clientId.hostHint")}>
              <Input value={form.clientIdHost} onChange={(e) => onChange({ clientIdHost: e.target.value })} placeholder="verifier.example.com"
                autoComplete="off" spellCheck={false} />
            </FormField>
            {san !== "none" && (
              <div className="hx-badges" role="status">
                {san === "match" && <Badge tone="success">{t("wallet.san.match")}</Badge>}
                {san === "mismatch" && <Badge tone="danger">{t("wallet.san.mismatch", { names: key?.certificate.dnsNames.join(", ") || t("wallet.key.noDnsNames") })}</Badge>}
                {san === "unknown" && <Badge tone="neutral">{t("wallet.san.unknown")}</Badge>}
              </div>
            )}
          </>
        )}
      </Section>

      {showDev && (
        <Section title={t("wallet.dev.title")} description={t("wallet.dev.desc")}>
          {!meta.devProfile && devKey.stored && !devKey.clearing && (
            <Alert tone="warning" title={t("wallet.dev.storedOutsideDevTitle")}>{t("wallet.dev.storedOutsideDev")}</Alert>
          )}
          <FormField label={t("wallet.dev.key")} hint={t("wallet.dev.keyHint")} error={fe("accessCertificatePrivateKey")} group>
            <SecretInput multiline label={t("wallet.dev.key")} value={devKey.value} stored={devKey.stored}
              replacing={devKey.replacing} clearing={devKey.clearing}
              onChange={meta.devProfile ? devKey.onChange : () => undefined}
              onReplace={meta.devProfile ? devKey.onReplace : () => undefined} onClear={devKey.onClear} />
          </FormField>
          {meta.devProfile && (
            <FormField label={t("wallet.dev.chain")} hint={t("wallet.dev.chainHint")} error={fe("accessCertificateChain")}>
              <Textarea className="hx-mono" rows={4} value={form.accessCertificateChain} spellCheck={false}
                onChange={(e) => onChange({ accessCertificateChain: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----…" />
            </FormField>
          )}
        </Section>
      )}
    </>
  );
}

/** Import a key + chain into the realm's key store; the server's refusals land on the same fields. */
function KeyImportPanel({ realmId, api, onImported, onCancel }: {
  realmId: string; api: WalletAdminApi; onImported: (key: VerifierKey) => void; onCancel: () => void;
}) {
  const { t } = useT();
  const [draft, setDraft] = React.useState<KeyImportForm>({ name: "", privateKeyPem: "", certificateChainPem: "" });
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const [other, setOther] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const set = (patch: Partial<KeyImportForm>) => setDraft((d) => ({ ...d, ...patch }));
  const fe = useFieldError(errors);

  const submit = async () => {
    const local = validateKeyImport(draft);
    setErrors(local);
    setOther(null);
    if (Object.keys(local).length) return;
    setBusy(true);
    try {
      onImported(await api.importKey(realmId, { ...draft, name: draft.name.trim() }));
    } catch (e: unknown) {
      if (e instanceof AdminApiError && Object.keys(e.fieldErrors).length) {
        const known = ["name", "privateKeyPem", "certificateChainPem"];
        setErrors(Object.fromEntries(Object.entries(e.fieldErrors).filter(([k]) => known.includes(k))));
        const rest = Object.entries(e.fieldErrors).filter(([k]) => !known.includes(k)).map(([, v]) => v);
        if (rest.length) setOther(rest.join(" "));
      } else {
        setOther(String((e as Error).message ?? e));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="hx-subpanel" role="group" aria-label={t("wallet.import.title")}>
      <div className="hx-subpanel__head">
        <strong>{t("wallet.import.title")}</strong>
        <span className="hx-help">{t("wallet.import.desc")}</span>
      </div>
      {other && <Alert tone="danger">{other}</Alert>}
      <FormField label={t("wallet.import.name")} required error={fe("name")} hint={t("wallet.import.nameHint")}>
        <Input value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="eudi-access-2026" autoComplete="off" spellCheck={false} />
      </FormField>
      <FormField label={t("wallet.import.privateKey")} required error={fe("privateKeyPem")} hint={t("wallet.import.privateKeyHint")}>
        <Textarea className="hx-mono" rows={4} value={draft.privateKeyPem} onChange={(e) => set({ privateKeyPem: e.target.value })}
          placeholder="-----BEGIN PRIVATE KEY-----…" spellCheck={false} autoComplete="off" />
      </FormField>
      <FormField label={t("wallet.import.chain")} required error={fe("certificateChainPem")} hint={t("wallet.import.chainHint")}>
        <Textarea className="hx-mono" rows={5} value={draft.certificateChainPem} onChange={(e) => set({ certificateChainPem: e.target.value })}
          placeholder="-----BEGIN CERTIFICATE-----…" spellCheck={false} />
      </FormField>
      <div className="hx-formactions">
        <div className="hx-inlineactions">
          <FileButton label={`${t("wallet.loadFile")}: ${t("wallet.import.privateKey")}`} onText={(v) => set({ privateKeyPem: v })} />
          <FileButton label={`${t("wallet.loadFile")}: ${t("wallet.import.chain")}`} onText={(v) => set({ certificateChainPem: v })} />
        </div>
        <div className="hx-inlineactions">
          <Button variant="ghost" onClick={onCancel} disabled={busy}>{t("wallet.import.cancel")}</Button>
          <Button variant="primary" onClick={submit} disabled={busy}>{busy ? t("wallet.import.importing") : t("wallet.import.submit")}</Button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------------- credentials

export function WalletCredentialsSection(props: WalletSectionProps) {
  const { realmId, api, form, onChange, errors, meta, original } = props;
  const { t, locale } = useT();
  const fe = useFieldError(errors);
  const warnings = walletWarnings(form, original);
  const toggleFormat = (f: string, on: boolean) =>
    onChange({ credentialFormats: on ? [...form.credentialFormats.filter((x) => x !== f), f] : form.credentialFormats.filter((x) => x !== f) });
  const toggleClaim = (c: string, on: boolean) =>
    onChange({ requestedClaims: on ? [...form.requestedClaims.filter((x) => x !== c), c] : form.requestedClaims.filter((x) => x !== c) });

  const [preview, setPreview] = React.useState<{ pem: string; certs: CertificateInfo[] } | null>(null);
  const [previewError, setPreviewError] = React.useState<string | null>(null);
  const [previewing, setPreviewing] = React.useState(false);
  const runPreview = async () => {
    setPreviewing(true);
    setPreviewError(null);
    try {
      const certs = await api.previewCertificates(realmId, form.trustAnchors);
      setPreview({ pem: form.trustAnchors, certs });
    } catch (e: unknown) {
      setPreview(null);
      setPreviewError(e instanceof AdminApiError ? (e.fieldErrors.pem ?? e.message) : String((e as Error).message ?? e));
    } finally {
      setPreviewing(false);
    }
  };

  return (
    <>
      <Section title={t("wallet.formats.title")} description={t("wallet.formats.desc")}>
        <FormField label={t("wallet.formats.field")} required error={fe("credentialFormats")} group>
          <div className="hx-optiongrid">
            <Checkbox checked={form.credentialFormats.includes(SD_JWT_FORMAT)} onChange={(on) => toggleFormat(SD_JWT_FORMAT, on)}
              label={<span className="hx-optlabel"><span>{t("wallet.format.sdjwt")}</span><span className="hx-optlabel__sub">{t("wallet.format.sdjwtDesc")}</span></span>} />
            <Checkbox checked={form.credentialFormats.includes(MDOC_FORMAT)} onChange={(on) => toggleFormat(MDOC_FORMAT, on)}
              label={<span className="hx-optlabel"><span>{t("wallet.format.mdoc")}</span><span className="hx-optlabel__sub">{t("wallet.format.mdocDesc")}</span></span>} />
          </div>
        </FormField>
      </Section>

      <Section title={t("wallet.claims.title")} description={t("wallet.claims.desc")}
        actions={<Badge tone={warnings.includes("manyClaims") ? "warning" : "neutral"}>{t("wallet.claims.count", { n: form.requestedClaims.length })}</Badge>}>
        {warnings.includes("manyClaims") && <Alert tone="warning" title={t("wallet.warn.manyClaims.title")}>{t("wallet.warn.manyClaims")}</Alert>}
        {warnings.includes("adminNumberWithoutStrategy") && (
          <Alert tone="warning" title={t("wallet.warn.adminNumberWithoutStrategy.title")}>{t("wallet.warn.adminNumberWithoutStrategy")}</Alert>
        )}
        {warnings.includes("placeOfBirthOrphans") && (
          <Alert tone="danger" title={t("wallet.warn.placeOfBirthOrphans.title")}>{t("wallet.warn.placeOfBirthOrphans")}</Alert>
        )}
        <FormField label={t("wallet.claims.field")} required error={fe("pid.requestedClaims")} group>
          <div className="hx-optiongrid hx-optiongrid--claims">
            {meta.pidClaims.map((c) => (
              <Checkbox key={c.name} checked={form.requestedClaims.includes(c.name)} onChange={(on) => toggleClaim(c.name, on)}
                label={
                  <span className="hx-optlabel">
                    <span>{t(`wallet.claim.${c.name}`)}{!c.mdoc && <> <Badge tone="neutral">{t("wallet.claims.sdJwtOnly")}</Badge></>}</span>
                    <span className="hx-optlabel__sub hx-mono">{c.name}</span>
                  </span>
                } />
            ))}
          </div>
        </FormField>
      </Section>

      <Section title={t("wallet.anchors.title")} description={t("wallet.anchors.desc")}>
        <FormField label={t("wallet.anchors.field")} required error={fe("trustAnchors")} hint={t("wallet.anchors.hint")}>
          <Textarea className="hx-mono" rows={6} value={form.trustAnchors} spellCheck={false}
            onChange={(e) => onChange({ trustAnchors: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----…" />
        </FormField>
        <div className="hx-inlineactions">
          <FileButton label={t("wallet.loadFile")} onText={(v) => onChange({ trustAnchors: v })} />
          <Button variant="ghost" onClick={runPreview} disabled={previewing || !form.trustAnchors.trim()}>
            {previewing ? t("wallet.anchors.previewing") : t("wallet.anchors.preview")}
          </Button>
        </div>
        {previewError && <Alert tone="danger" title={t("wallet.anchors.previewFailed")}>{t(previewError)}</Alert>}
        {preview && (
          <div className="hx-certpreview" aria-live="polite">
            {preview.pem !== form.trustAnchors && <Alert tone="info">{t("wallet.anchors.stale")}</Alert>}
            <div className="hx-help">{t("wallet.anchors.previewCount", { n: preview.certs.length })}</div>
            <ul className="hx-certlist">
              {preview.certs.map((c, i) => (
                <li key={`${c.serialNumber}-${i}`} className="hx-certlist__item">
                  <div className="hx-certlist__head">
                    <strong>{commonName(c.subject)}</strong>
                    <span className="hx-badges">
                      <Badge tone={c.ca ? "accent" : "danger"}>{c.ca ? t("wallet.anchors.ca") : t("wallet.anchors.notCa")}</Badge>
                      {c.selfSigned && <Badge tone="neutral">{t("wallet.anchors.root")}</Badge>}
                      <ExpiryBadge notAfter={c.notAfter} />
                    </span>
                  </div>
                  <div className="hx-certlist__meta">
                    <span>{t("wallet.key.issuer")}: {commonName(c.issuer)}</span>
                    <span>{t("wallet.key.validUntil")}: {absoluteTime(c.notAfter, locale)}</span>
                    <span>{c.keyAlgorithm}</span>
                  </div>
                  <div className="hx-certlist__dn hx-mono">{c.subject}</div>
                  {c.trustAnchorProblem
                    ? <div className="hx-field__error">{c.trustAnchorProblem}</div>
                    : <div className="hx-certlist__ok">{t("wallet.anchors.usable")}</div>}
                </li>
              ))}
            </ul>
          </div>
        )}
        <FormField label={t("wallet.revocation.field")} group="radiogroup" error={fe("revocationChecking")}>
          <div className="hx-choicegrid">
            <RadioCard roving selected={form.revocationChecking === "HARD_FAIL"} onSelect={() => onChange({ revocationChecking: "HARD_FAIL" })}
              title={t("wallet.revocation.hardFail")} description={t("wallet.revocation.hardFailDesc")} />
            <RadioCard roving selected={form.revocationChecking === "SOFT_FAIL"} onSelect={() => onChange({ revocationChecking: "SOFT_FAIL" })}
              title={t("wallet.revocation.softFail")} description={t("wallet.revocation.softFailDesc")} />
            <RadioCard roving selected={form.revocationChecking === "OFF"} onSelect={() => onChange({ revocationChecking: "OFF" })}
              title={t("wallet.revocation.off")} description={t("wallet.revocation.offDesc")} />
          </div>
        </FormField>
        {form.revocationChecking === "SOFT_FAIL" && (
          <Alert tone="warning" title={t("wallet.warn.revocationSoftFail.title")}>{t("wallet.warn.revocationSoftFail")}</Alert>
        )}
        {form.revocationChecking === "OFF" && (
          <Alert tone="warning" title={t("wallet.warn.revocationOff.title")}>{t("wallet.warn.revocationOff")}</Alert>
        )}
        <FormField label={t("wallet.trustedAuthorities.field")} group="radiogroup" error={fe("dcql.trustedAuthorities")}>
          <div className="hx-choicegrid">
            <RadioCard roving selected={form.trustedAuthorities === "default"} onSelect={() => onChange({ trustedAuthorities: "default" })}
              title={t("wallet.trustedAuthorities.default")}
              description={t("wallet.trustedAuthorities.defaultDesc", {
                state: t(trustedAuthoritiesEffective({ ...form, trustedAuthorities: "default" })
                  ? "wallet.trustedAuthorities.stateOn" : "wallet.trustedAuthorities.stateOff"),
              })} />
            <RadioCard roving selected={form.trustedAuthorities === "on"} onSelect={() => onChange({ trustedAuthorities: "on" })}
              title={t("wallet.trustedAuthorities.on")} description={t("wallet.trustedAuthorities.onDesc")} />
            <RadioCard roving selected={form.trustedAuthorities === "off"} onSelect={() => onChange({ trustedAuthorities: "off" })}
              title={t("wallet.trustedAuthorities.off")} description={t("wallet.trustedAuthorities.offDesc")} />
          </div>
        </FormField>
      </Section>
    </>
  );
}

// ---------------------------------------------------------------------------------------------------- policies

export function WalletPoliciesSection(props: WalletSectionProps) {
  const { form, onChange, errors, meta, original } = props;
  const { t } = useT();
  const fe = useFieldError(errors);
  const warnings = walletWarnings(form, original);
  const requiredId = React.useId();
  const dcApiId = React.useId();

  return (
    <>
      <Section title={t("wallet.subject.title")} description={t("wallet.subject.desc")}>
        <FormField label={t("wallet.subject.field")} group="radiogroup" error={fe("subject.strategy")}>
          <div className="hx-choicegrid">
            <RadioCard roving selected={form.subjectStrategy === "ADMINISTRATIVE_NUMBER"}
              onSelect={() => onChange({ subjectStrategy: "ADMINISTRATIVE_NUMBER" })}
              title={t("wallet.subject.adminNumber")} description={t("wallet.subject.adminNumberDesc")} />
            <RadioCard roving selected={form.subjectStrategy === "ATTRIBUTE_TUPLE"}
              onSelect={() => onChange({ subjectStrategy: "ATTRIBUTE_TUPLE" })}
              title={t("wallet.subject.tuple")} description={t("wallet.subject.tupleDesc")} />
          </div>
        </FormField>
        {warnings.includes("weakTuple") && (
          <>
            <Alert tone="warning" title={t("wallet.warn.weakTuple.title")}>{t("wallet.warn.weakTuple")}</Alert>
            <Checkbox checked={form.acknowledgeWeakSubject} onChange={(on) => onChange({ acknowledgeWeakSubject: on })} label={t("wallet.subject.ack")} />
          </>
        )}
        {warnings.includes("adminNumberWithoutStrategy") && (
          <Alert tone="warning" title={t("wallet.warn.adminNumberWithoutStrategy.title")}>{t("wallet.warn.adminNumberWithoutStrategy")}</Alert>
        )}
        <FormField label={t("wallet.loa.field")} required error={fe("minimumLoa")} hint={t("wallet.loa.hint")}>
          <Select aria-label={t("wallet.loa.field")} value={form.minimumLoa} onChange={(v) => onChange({ minimumLoa: v })}
            options={LOA_LADDER.map((l) => ({ value: l.value, label: t(`wallet.loa.${l.key}`), description: l.value }))} />
        </FormField>
      </Section>

      <Section title={t("wallet.status.title")} description={t("wallet.status.desc")}>
        <div className="hx-switchrow">
          <div className="hx-switchrow__text">
            <span className="hx-switchrow__title" id={requiredId}>{t("wallet.status.required")}</span>
            <span className="hx-help">{t("wallet.status.requiredHint")}</span>
          </div>
          <Switch checked={form.statusRequired} onChange={(on) => onChange({ statusRequired: on })} ariaLabelledby={requiredId} />
        </div>
        <FormField label={t("wallet.status.onUnavailable")} group="radiogroup" error={fe("statusList.onUnavailable")}>
          <div className="hx-choicegrid">
            <RadioCard roving selected={form.onUnavailable === "FAIL_CLOSED"} onSelect={() => onChange({ onUnavailable: "FAIL_CLOSED" })}
              title={t("wallet.status.failClosed")} description={t("wallet.status.failClosedDesc")} />
            <RadioCard roving selected={form.onUnavailable === "FAIL_OPEN_WITH_AUDIT"} onSelect={() => onChange({ onUnavailable: "FAIL_OPEN_WITH_AUDIT" })}
              title={t("wallet.status.failOpen")} description={t("wallet.status.failOpenDesc")} />
          </div>
        </FormField>
        {warnings.includes("failOpen") && <Alert tone="warning" title={t("wallet.warn.failOpen.title")}>{t("wallet.warn.failOpen")}</Alert>}
        <div className="hx-fieldgrid">
          <FormField label={t("wallet.status.maxCache")} error={fe("statusList.maxCacheSeconds")} hint={t("wallet.status.maxCacheHint")}>
            <Input inputMode="numeric" value={form.statusMaxCacheSeconds} placeholder="900"
              onChange={(e) => onChange({ statusMaxCacheSeconds: e.target.value })} />
          </FormField>
          <FormField label={t("wallet.status.allowedHosts")} error={fe("statusList.allowedHosts")} hint={t("wallet.status.allowedHostsHint")}>
            <Input value={form.statusAllowedHosts} placeholder="status.pid-issuer.example" spellCheck={false}
              onChange={(e) => onChange({ statusAllowedHosts: e.target.value })} />
          </FormField>
        </div>
      </Section>

      <Section title={t("wallet.response.title")} description={t("wallet.response.desc")}>
        <FormField label={t("wallet.response.mode")} group="radiogroup" error={fe("responseMode")}
          hint={meta.devProfile ? undefined : t("wallet.response.plainDisabled")}>
          <div className="hx-choicegrid">
            <RadioCard roving selected={form.responseMode === "direct_post.jwt"} onSelect={() => onChange({ responseMode: "direct_post.jwt" })}
              title={t("wallet.response.jwt")} description={t("wallet.response.jwtDesc")} />
            <RadioCard roving selected={form.responseMode === "direct_post"} disabled={!meta.devProfile}
              onSelect={() => onChange({ responseMode: "direct_post" })}
              title={t("wallet.response.plain")} description={t("wallet.response.plainDesc")} />
          </div>
        </FormField>
        <div className="hx-fieldgrid">
          <FormField label={t("wallet.ttl.field")} error={fe("transactionTtlSeconds")} hint={t("wallet.ttl.hint")}>
            <Input inputMode="numeric" value={form.transactionTtlSeconds} placeholder={String(TTL_RANGE.default)}
              onChange={(e) => onChange({ transactionTtlSeconds: e.target.value })} />
          </FormField>
        </div>
      </Section>

      <Section title={t("wallet.dcApi.title")} description={t("wallet.dcApi.desc")}>
        <div className="hx-switchrow">
          <div className="hx-switchrow__text">
            <span className="hx-switchrow__title" id={dcApiId}>{t("wallet.dcApi.enabled")}</span>
            <span className="hx-help">{t("wallet.dcApi.enabledHint")}</span>
          </div>
          <Switch checked={form.dcApiEnabled} onChange={(on) => onChange({ dcApiEnabled: on })} ariaLabelledby={dcApiId} />
        </div>
        {form.dcApiEnabled && (
          <>
            <FormField label={t("wallet.dcApi.request")} group="radiogroup" error={fe("dcApi.request")}>
              <div className="hx-choicegrid">
                <RadioCard roving selected={form.dcApiRequest === "signed"} onSelect={() => onChange({ dcApiRequest: "signed" })}
                  title={t("wallet.dcApi.signed")} description={t("wallet.dcApi.signedDesc")} />
                <RadioCard roving selected={form.dcApiRequest === "unsigned"} onSelect={() => onChange({ dcApiRequest: "unsigned" })}
                  title={t("wallet.dcApi.unsigned")} description={t("wallet.dcApi.unsignedDesc")} />
              </div>
            </FormField>
            {warnings.includes("dcApiUnsigned") && (
              <Alert tone="warning" title={t("wallet.warn.dcApiUnsigned.title")}>{t("wallet.warn.dcApiUnsigned")}</Alert>
            )}
          </>
        )}
        <FormField label={t("wallet.dcApi.origins")} error={fe("dcApi.expectedOrigins")} hint={t("wallet.dcApi.originsHint")}>
          <Textarea className="hx-mono" rows={3} value={form.dcApiExpectedOrigins} spellCheck={false}
            placeholder="https://login.example.eu" onChange={(e) => onChange({ dcApiExpectedOrigins: e.target.value })} />
        </FormField>
      </Section>
    </>
  );
}

// ---------------------------------------------------------------------------------------------------- review

/** The wizard's last step: what will be saved, in words (raw ids only as muted technical lines). */
export function WalletReview({ form, keys }: { form: WalletForm; keys: VerifierKey[] }) {
  const { t } = useT();
  const key = keys.find((k) => k.keyRef === form.accessKeyRef.trim());
  const anchors = (form.trustAnchors.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
  const hosts = parseHostList(form.statusAllowedHosts);
  return (
    <DetailList>
      <Detail label={t("wallet.review.key")} sub={key ? commonName(key.certificate.subject) : undefined} mono={form.accessKeyRef || undefined}>
        {key?.name ?? "—"}
      </Detail>
      <Detail label={t("wallet.review.clientId")}>
        {form.clientIdScheme === "x509_hash" ? t("wallet.clientId.hash") : `${t("wallet.clientId.sanDns")} · ${form.clientIdHost}`}
      </Detail>
      <Detail label={t("wallet.review.formats")}>
        {form.credentialFormats.map((f) => (f === SD_JWT_FORMAT ? t("wallet.format.sdjwt") : t("wallet.format.mdoc"))).join(", ") || "—"}
      </Detail>
      <Detail label={t("wallet.review.claims")}>{form.requestedClaims.map((c) => t(`wallet.claim.${c}`)).join(", ") || "—"}</Detail>
      <Detail label={t("wallet.review.anchors")}>{t("wallet.review.anchorsCount", { n: anchors })}</Detail>
      <Detail label={t("wallet.review.revocation")}>
        {t(form.revocationChecking === "HARD_FAIL" ? "wallet.revocation.hardFail"
          : form.revocationChecking === "SOFT_FAIL" ? "wallet.revocation.softFail" : "wallet.revocation.off")}
      </Detail>
      <Detail label={t("wallet.review.trustedAuthorities")}>
        {t(trustedAuthoritiesEffective(form) ? "wallet.trustedAuthorities.on" : "wallet.trustedAuthorities.off")}
      </Detail>
      <Detail label={t("wallet.review.subject")}>
        {form.subjectStrategy === "ADMINISTRATIVE_NUMBER" ? t("wallet.subject.adminNumber") : t("wallet.subject.tuple")}
      </Detail>
      <Detail label={t("wallet.review.status")} sub={hosts.length ? hosts.join(", ") : undefined}>
        {`${form.statusRequired ? t("wallet.review.statusRequired") : t("wallet.review.statusOptional")} · ${form.onUnavailable === "FAIL_CLOSED" ? t("wallet.status.failClosed") : t("wallet.status.failOpen")}`}
      </Detail>
      <Detail label={t("wallet.review.response")}>{form.responseMode === "direct_post.jwt" ? t("wallet.response.jwt") : t("wallet.response.plain")}</Detail>
      <Detail label={t("wallet.review.dcApi")} sub={form.dcApiEnabled && parseOriginList(form.dcApiExpectedOrigins).length
        ? parseOriginList(form.dcApiExpectedOrigins).join(", ") : undefined}>
        {form.dcApiEnabled ? t(form.dcApiRequest === "signed" ? "wallet.dcApi.signed" : "wallet.dcApi.unsigned")
          : t("wallet.review.dcApiOff")}
      </Detail>
      <Detail label={t("wallet.review.ttl")}>{t("wallet.review.ttlValue", { n: form.transactionTtlSeconds.trim() || TTL_RANGE.default })}</Detail>
    </DetailList>
  );
}
