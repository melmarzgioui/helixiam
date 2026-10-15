/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Stepper } from "./Stepper";
import { Button } from "./Button";
import { FormField, Input } from "./FormField";
import { Select } from "./Select";
import { Checkbox } from "./Choice";
import { Switch } from "./Switch";
import { Divider } from "./Divider";
import { Spinner } from "./Spinner";
import { ProviderLogo } from "./ProviderLogo";
import { ProviderTile } from "./ProviderTile";
import { LoaBadge } from "./LoaBadge";
import { Badge } from "./Badge";
import { MetadataUpload } from "./MetadataUpload";
import { PROVIDER_TYPES, DEFAULT_MAPPERS, findProviderType, loaBandOf, missingConnectionFields, ProviderType, AttributeMapper } from "./providerCatalog";
import { Alert } from "./Alert";
import { Section } from "./Page";
import {
  WalletAccessSection, WalletCredentialsSection, WalletPoliciesSection, WalletReview, useWalletData, walletContext,
} from "./WalletProviderForm";
import type { WalletAdminApi } from "../api/wallet";
import {
  DEFAULT_WALLET_FORM, DEV_KEY, clearEditedErrors, firstErrorSection, splitWalletServerErrors, validateWallet,
  walletConfigFromForm, walletFormFromConfig, walletLinkOptions, defaultWalletAlias, type WalletForm, type WalletSection,
} from "../pages/walletProvider";
import { useT } from "../i18n/LocaleContext";

const STEPS = ["Provider", "Connection", "Mappers", "Review"];
/** The wallet's steps: provider, connection (+ access key), credentials, policies, review. */
const WALLET_STEP_OF: Record<WalletSection, number> = { general: 1, access: 1, credentials: 2, policies: 3 };

export interface WizardResult {
  providerType: string;
  alias: string;
  displayName: string;
  config: Record<string, string>;
  mappers: AttributeMapper[];
  enabled: boolean;
}

export interface ProviderWizardProps {
  onComplete?: (result: WizardResult) => void;
  onCancel?: () => void;
  /** When set, the wizard edits an existing connection instead of creating a new one. */
  initial?: WizardResult;
  /** The realm and the wallet admin API: needed to offer the EUDI Wallet provider (keys, claim catalogue). */
  realmId?: string;
  walletApi?: WalletAdminApi;
  /** A save is in flight: the final button is disabled. */
  busy?: boolean;
  /** The fieldErrors of a refused save (400): shown on the wizard's fields, opening the step that holds them. */
  serverErrors?: Record<string, string> | null;
  /** The realm's connections: a verify-only wallet connection picks its linked sign-in connection from them. */
  providers?: { alias: string; protocol: string; displayName: string; config?: Record<string, string> }[];
}

/** Splits a stored mapper list into the ticked presets vs the free-form custom rows. */
function seedMappers(typeId: string | null, mappers: AttributeMapper[]) {
  const type = typeId ? findProviderType(typeId) : undefined;
  const presetSrc = new Set(type ? DEFAULT_MAPPERS[type.protocol].map((m) => m.source) : []);
  return {
    presets: mappers.filter((m) => presetSrc.has(m.source)).map((m) => m.source),
    custom: mappers.filter((m) => !presetSrc.has(m.source)),
  };
}

/** The E8.4 "Add identity provider" wizard, composed from the design system. */
export function ProviderWizard({ onComplete, onCancel, initial, realmId, walletApi, busy, serverErrors, providers }: ProviderWizardProps) {
  const { t } = useT();
  const editing = !!initial;
  const seeded = seedMappers(initial?.providerType ?? null, initial?.mappers ?? []);
  const [step, setStep] = React.useState(editing ? 1 : 0);
  const [typeId, setTypeId] = React.useState<string | null>(initial?.providerType ?? null);
  const [alias, setAlias] = React.useState(initial?.alias ?? "");
  const [displayName, setDisplayName] = React.useState(initial?.displayName ?? "");
  const [config, setConfig] = React.useState<Record<string, string>>(initial?.config ?? {});
  const [presetSources, setPresetSources] = React.useState<string[]>(seeded.presets);
  const [customMappers, setCustomMappers] = React.useState<AttributeMapper[]>(seeded.custom);
  const [enabled, setEnabled] = React.useState(initial?.enabled ?? true);
  const [attempted, setAttempted] = React.useState(false); // show field errors after a failed Continue

  const type = typeId ? findProviderType(typeId) : undefined;
  const missing = step === 1 && type ? missingConnectionFields(type, config, alias, displayName) : [];

  // ---- EUDI Wallet: its own form model and steps (pages/walletProvider.ts, WalletProviderForm.tsx).
  const isWallet = type?.protocol === "wallet";
  const offered = walletApi && realmId ? PROVIDER_TYPES : PROVIDER_TYPES.filter((p) => p.protocol !== "wallet");
  const steps = isWallet ? ["Provider", t("wallet.step.connection"), t("wallet.step.credentials"), t("wallet.step.policies"), "Review"] : STEPS;
  const wallet = useWalletData(walletApi, realmId, isWallet);
  const [walletForm, setWalletForm] = React.useState<WalletForm>(() =>
    initial && findProviderType(initial.providerType)?.protocol === "wallet" ? walletFormFromConfig(initial.config) : DEFAULT_WALLET_FORM);
  const [devKey, setDevKey] = React.useState({ value: "", replacing: false, clearing: false });
  const [walletServer, setWalletServer] = React.useState<{ fields: Record<string, string>; other: string[] }>({ fields: {}, other: [] });
  const devKeyState = {
    stored: false, ...devKey,
    onChange: (v: string) => setDevKey((d) => ({ ...d, value: v })),
    onReplace: (on: boolean) => setDevKey((d) => ({ ...d, replacing: on, value: on ? d.value : "" })),
    onClear: (on: boolean) => setDevKey((d) => ({ ...d, clearing: on, value: "" })),
  };
  const linkOptions = providers ? walletLinkOptions(providers, alias.trim()) : undefined;
  const walletLocal = isWallet ? validateWallet(walletForm, { ...walletContext(walletForm, wallet.meta, wallet.keys, devKeyState, wallet.lists),
    alias: alias.trim(), linkedAliases: linkOptions?.map((o) => o.alias) }) : {};
  if (isWallet && !alias.trim()) walletLocal.alias = "connectionDetail.fieldRequired";
  if (isWallet && !displayName.trim()) walletLocal.displayName = "connectionDetail.fieldRequired";
  const walletShown = { ...walletServer.fields, ...(attempted ? walletLocal : {}) };
  const walletStepErrors = (s: number) => Object.keys(walletLocal).filter((k) => {
    const section = firstErrorSection({ [k]: "x" });
    return section !== null && WALLET_STEP_OF[section] === s;
  });
  const existingAliases = (providers ?? []).map((p) => p.alias);
  // The alias the wizard proposed (unique in the realm); it follows the strategy until the admin edits it.
  const [autoAlias, setAutoAlias] = React.useState<string | null>(null);
  const patchWallet = (patch: Partial<WalletForm>) => {
    if (patch.subjectStrategy !== undefined && !editing && autoAlias !== null && alias === autoAlias) {
      const next = defaultWalletAlias(existingAliases, patch.subjectStrategy === "NONE");
      setAlias(next);
      setAutoAlias(next);
    }
    setWalletForm((f) => ({ ...f, ...patch }));
    setWalletServer((sv) => ({ ...sv, fields: clearEditedErrors(sv.fields, patch) }));
  };
  React.useEffect(() => {
    if (!serverErrors || !isWallet) return;
    const split = splitWalletServerErrors(serverErrors);
    setWalletServer(split);
    const section = firstErrorSection(split.fields);
    if (section) setStep(WALLET_STEP_OF[section]);
  }, [serverErrors]); // eslint-disable-line react-hooks/exhaustive-deps

  const pickType = (t: ProviderType) => {
    setTypeId(t.id);
    const proposed = t.protocol === "wallet" ? defaultWalletAlias(existingAliases, false) : t.id;
    setAlias(proposed);
    setAutoAlias(t.protocol === "wallet" ? proposed : null);
    setDisplayName(t.protocol === "wallet" ? "EUDI Wallet" : t.name);
    setWalletForm(DEFAULT_WALLET_FORM);
    setConfig(t.defaultLoaValue ? { minimumLoa: t.defaultLoaValue } : {});
    setPresetSources(DEFAULT_MAPPERS[t.protocol].filter((m) => m.required).map((m) => m.source));
    setCustomMappers([]);
  };

  const set = (k: string, v: string) => setConfig((c) => ({ ...c, [k]: v }));
  const unset = (k: string) => setConfig(({ [k]: _drop, ...rest }) => rest);
  const togglePreset = (source: string, on: boolean) =>
    setPresetSources((m) => (on ? [...new Set([...m, source])] : m.filter((x) => x !== source)));

  // The mappers the wizard ultimately emits: the ticked presets, then the non-empty custom rows.
  const builtMappers = (): AttributeMapper[] => [
    ...(type ? DEFAULT_MAPPERS[type.protocol].filter((m) => presetSources.includes(m.source)).map((m) => ({ source: m.source, target: m.target })) : []),
    ...customMappers.filter((m) => m.source.trim() && m.target.trim()),
  ];

  const firstStep = editing ? 1 : 0; // in edit mode the provider is fixed — start at Connection
  const canNext = step === 0 ? !!type : true; // the Connection step validates on click, not by disabling
  const next = () => {
    if (isWallet) {
      if (step >= 1 && step < steps.length - 1 && walletStepErrors(step).length) { setAttempted(true); return; }
      if (step < steps.length - 1) { setAttempted(false); setStep(step + 1); return; }
      const all = Object.keys(walletLocal);
      if (all.length) {
        setAttempted(true);
        const section = firstErrorSection(walletLocal);
        if (section) setStep(WALLET_STEP_OF[section]);
        return;
      }
      if (type) {
        const walletConfig = walletConfigFromForm(walletForm, {});
        if (devKey.value.trim()) walletConfig[DEV_KEY] = devKey.value;
        onComplete?.({ providerType: type.id, alias: alias.trim(), displayName: displayName.trim(), config: walletConfig, mappers: [], enabled });
      }
      return;
    }
    if (step === 1) {
      if (missing.length) { setAttempted(true); return; } // block + reveal errors
    }
    if (step < steps.length - 1) { setAttempted(false); setStep(step + 1); }
    else if (type) onComplete?.({ providerType: type.id, alias, displayName, config, mappers: builtMappers(), enabled });
  };
  const back = () => { setAttempted(false); step > firstStep ? setStep(step - 1) : onCancel?.(); };

  return (
    <div className="hx-wizard">
      <div className="hx-wizard__steps">
        <Stepper steps={steps} current={step} />
      </div>

      {step === 0 && (
        <div className="hx-wizard__tiles">
          {offered.map((t) => (
            <ProviderTile
              key={t.id}
              kind={t.kind}
              title={t.name}
              description={t.description}
              selected={typeId === t.id}
              onSelect={() => pickType(t)}
              tag={t.loaOptions ? <Badge tone="neutral">eID</Badge> : undefined}
            />
          ))}
        </div>
      )}

      {isWallet && step > 0 && walletServer.other.length > 0 && (
        <Alert tone="danger" title={t("wallet.serverErrors")}>{walletServer.other.join(" ")}</Alert>
      )}
      {isWallet && step > 0 && step < steps.length - 1 && wallet.error && <Alert tone="danger" title={t("wallet.errMeta")}>{wallet.error}</Alert>}
      {isWallet && step > 0 && step < steps.length - 1 && !wallet.error && (!wallet.meta || !wallet.keys) && (
        <div className="hx-loadwrap"><Spinner size={28} label={t("wallet.loadingMeta")} /></div>
      )}
      {isWallet && type && step > 0 && wallet.meta && wallet.keys && realmId && walletApi && (() => {
        const props = {
          realmId, api: walletApi, form: walletForm, onChange: patchWallet, errors: walletShown, meta: wallet.meta,
          keys: wallet.keys, onKeyImported: wallet.addKey, original: null, devKey: devKeyState, linkedOptions: linkOptions,
          trustedLists: wallet.lists, trustedListsError: wallet.listsError,
        };
        return (
          <div className="hx-stack hx-wallet">
            {step === 1 && (
              <>
                <Section title={type.name} description={type.description}>
                  <FormField label="Alias" required error={walletShown.alias ? t(walletShown.alias) : undefined}
                    hint={editing ? "The connection's stable id — fixed once created." : "Stable id used in the broker callback URL."}>
                    <Input value={alias} onChange={(e) => setAlias(e.target.value)} readOnly={editing} disabled={editing} />
                  </FormField>
                  <FormField label="Display name" required error={walletShown.displayName ? t(walletShown.displayName) : undefined}>
                    <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
                  </FormField>
                </Section>
                <WalletAccessSection {...props} />
              </>
            )}
            {step === 2 && <WalletCredentialsSection {...props} />}
            {step === 3 && <WalletPoliciesSection {...props} />}
            {step === 4 && (
              <Section title={type.name}>
                <WalletReview form={walletForm} keys={wallet.keys} linkedOptions={linkOptions} />
                <Switch checked={enabled} onChange={setEnabled} label="Enable immediately after creation" />
              </Section>
            )}
          </div>
        );
      })()}

      {!isWallet && step === 1 && type && (
        <ConnectionForm type={type} alias={alias} setAlias={setAlias} displayName={displayName} setDisplayName={setDisplayName} config={config} set={set} unset={unset} lockAlias={editing} errors={attempted ? missing : []} />
      )}

      {!isWallet && step === 2 && type && (
        <MappersStep
          type={type}
          presetSources={presetSources}
          togglePreset={togglePreset}
          customMappers={customMappers}
          setCustomMappers={setCustomMappers}
        />
      )}

      {!isWallet && step === 3 && type && (
        <ReviewStep type={type} alias={alias} displayName={displayName} config={config} mappers={builtMappers()} enabled={enabled} setEnabled={setEnabled} />
      )}

      <Divider gap="1.5rem" />
      <div className="hx-wizard__nav">
        <Button variant="ghost" onClick={back}>{step === firstStep ? "Cancel" : "Back"}</Button>
        <Button variant="primary" onClick={next} disabled={!canNext || (busy && step === steps.length - 1)}>
          {step === steps.length - 1 ? (editing ? "Save changes" : "Create connection") : "Continue"}
        </Button>
      </div>
    </div>
  );
}

const CUSTOM_LOA = "__custom__";

function ConnectionForm({
  type, alias, setAlias, displayName, setDisplayName, config, set, unset, lockAlias, errors,
}: {
  type: ProviderType;
  alias: string; setAlias: (v: string) => void;
  displayName: string; setDisplayName: (v: string) => void;
  config: Record<string, string>; set: (k: string, v: string) => void; unset: (k: string) => void;
  lockAlias?: boolean; errors: string[];
}) {
  const loaValues = type.loaOptions?.map((o) => o.value) ?? [];
  const [loaCustom, setLoaCustom] = React.useState(
    () => config.minimumLoa !== undefined && config.minimumLoa !== "" && !loaValues.includes(config.minimumLoa)
  );
  const err = (key: string, msg = "This field is required.") => (errors.includes(key) ? msg : undefined);
  return (
    <div>
      <div className="hx-wizard__head">
        <ProviderLogo kind={type.kind} size={32} />
        <strong className="hx-wizard__head-title">{type.name}</strong>
      </div>

      <FormField label="Alias" required error={err("alias")} hint={lockAlias ? "The connection's stable id — fixed once created." : "Stable id used in the broker callback URL."}>
        <Input value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="digid" readOnly={lockAlias} disabled={lockAlias} />
      </FormField>
      <FormField label="Display name" required error={err("displayName")}>
        <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
      </FormField>

      {type.protocol === "oidc" && (
        <>
          <FormField label="Issuer / discovery URL" required error={err("issuer")} hint="…/.well-known/openid-configuration is resolved automatically.">
            <Input value={config.issuer ?? ""} onChange={(e) => set("issuer", e.target.value)} placeholder="https://accounts.example.com" />
          </FormField>
          <FormField label="Client ID" required error={err("clientId")}>
            <Input value={config.clientId ?? ""} onChange={(e) => set("clientId", e.target.value)} />
          </FormField>
          <FormField label="Client secret">
            <Input type="password" value={config.clientSecret ?? ""} onChange={(e) => set("clientSecret", e.target.value)} />
          </FormField>
        </>
      )}

      {type.protocol === "saml" && (
        <>
          <FormField
            label="IdP metadata URL"
            required={!type.metadataImport}
            error={err("metadata", type.metadataImport ? "Provide a metadata URL or upload the XML below." : "This field is required.")}
            hint={type.metadataImport ? "Paste the IdP metadata URL, or upload the metadata XML below." : undefined}
          >
            <Input value={config.metadataUrl ?? ""} onChange={(e) => set("metadataUrl", e.target.value)} placeholder="https://idp.example/metadata" />
          </FormField>
          {type.metadataImport && (
            <div className="hx-wizard__upload">
              <MetadataUpload
                fileName={config.metadataFileName}
                onLoaded={(name, xml) => { set("metadataFileName", name); set("metadataXml", xml); }}
                onClear={() => { unset("metadataFileName"); unset("metadataXml"); }}
              />
            </div>
          )}
          <FormField label="SP entity ID" required error={err("entityId")}>
            <Input value={config.entityId ?? ""} onChange={(e) => set("entityId", e.target.value)} placeholder="https://helix.example/sp" />
          </FormField>
          {type.loaOptions && (
            <FormField
              label="Minimum level of assurance"
              required
              error={err("minimumLoa")}
              hint={loaCustom ? "Enter the exact assurance level or URN the IdP asserts." : `The lowest ${type.name.replace(/\s*\(.*\)/, "")} assurance level this connection will accept.`}
            >
              <Select
                value={loaCustom ? CUSTOM_LOA : (config.minimumLoa ?? type.defaultLoaValue)}
                onChange={(v) => {
                  if (v === CUSTOM_LOA) { setLoaCustom(true); set("minimumLoa", ""); }
                  else { setLoaCustom(false); set("minimumLoa", v); }
                }}
                aria-label="Minimum level of assurance"
                options={[
                  ...type.loaOptions.map((o) => ({ value: o.value, label: o.label, description: o.description })),
                  { value: CUSTOM_LOA, label: "Other (custom)…", description: "Specify a level or URN not listed above" },
                ]}
              />
              {loaCustom && (
                <Input
                  className="hx-wizard__loacustom"
                  value={config.minimumLoa ?? ""}
                  onChange={(e) => set("minimumLoa", e.target.value)}
                  aria-label="Custom level of assurance"
                  placeholder="urn:oasis:names:tc:SAML:2.0:ac:classes:…"
                />
              )}
            </FormField>
          )}
        </>
      )}

      {type.protocol === "ldap" && (
        <>
          <FormField label="Connection URL" required>
            <Input value={config.url ?? ""} onChange={(e) => set("url", e.target.value)} placeholder="ldaps://dc.example.com:636" />
          </FormField>
          <FormField label="Bind DN" required>
            <Input value={config.bindDn ?? ""} onChange={(e) => set("bindDn", e.target.value)} placeholder="cn=svc,ou=apps,dc=example,dc=com" />
          </FormField>
          <FormField label="Bind credential">
            <Input type="password" value={config.bindPw ?? ""} onChange={(e) => set("bindPw", e.target.value)} />
          </FormField>
        </>
      )}
    </div>
  );
}

function MappersStep({
  type, presetSources, togglePreset, customMappers, setCustomMappers,
}: {
  type: ProviderType;
  presetSources: string[]; togglePreset: (source: string, on: boolean) => void;
  customMappers: AttributeMapper[]; setCustomMappers: React.Dispatch<React.SetStateAction<AttributeMapper[]>>;
}) {
  const editCustom = (i: number, patch: Partial<AttributeMapper>) =>
    setCustomMappers((rows) => rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addCustom = () => setCustomMappers((rows) => [...rows, { source: "", target: "" }]);
  const removeCustom = (i: number) => setCustomMappers((rows) => rows.filter((_, j) => j !== i));

  return (
    <div>
      <p className="hx-wizard__intro">
        Map {type.protocol.toUpperCase()} attributes onto the user profile. Tick the common ones, or add your own.
      </p>

      <div className="hx-wizard__presets">
        {DEFAULT_MAPPERS[type.protocol].map((m) => (
          <Checkbox
            key={m.source}
            label={`${m.source} → ${m.target}`}
            disabled={m.required}
            checked={presetSources.includes(m.source)}
            onChange={(on) => togglePreset(m.source, on)}
          />
        ))}
      </div>

      {customMappers.length > 0 && (
        <div className="hx-wizard__custom">
          <span className="hx-wizard__custom-title">Custom attributes</span>
          {customMappers.map((m, i) => (
            <div key={i} className="hx-wizard__custom-row">
              <Input
                value={m.source}
                onChange={(e) => editCustom(i, { source: e.target.value })}
                aria-label={`Custom attribute ${i + 1} source`}
                placeholder="IdP attribute (e.g. department)"
              />
              <span aria-hidden="true" className="hx-wizard__custom-arrow">→</span>
              <Input
                value={m.target}
                onChange={(e) => editCustom(i, { target: e.target.value })}
                aria-label={`Custom attribute ${i + 1} target`}
                placeholder="user attribute"
              />
              <button
                type="button"
                className="hx-ghosticon hx-ghosticon--36"
                aria-label={`Remove custom attribute ${i + 1}`}
                onClick={() => removeCustom(i)}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                </svg>
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="hx-wizard__addattr">
        <Button variant="ghost" onClick={addCustom}>+ Add attribute</Button>
      </div>
    </div>
  );
}

function ReviewStep({
  type, alias, displayName, config, mappers, enabled, setEnabled,
}: {
  type: ProviderType; alias: string; displayName: string;
  config: Record<string, string>; mappers: AttributeMapper[];
  enabled: boolean; setEnabled: (v: boolean) => void;
}) {
  const row = (k: string, v: React.ReactNode) => (
    <div key={k} className="hx-wizard__kv">
      <span className="hx-wizard__kv-key">{k}</span>
      <span className="hx-wizard__kv-val">{v}</span>
    </div>
  );
  const secret = (v?: string) => (v ? "••••••••" : "—");
  const loaValue = config.minimumLoa ?? type.defaultLoaValue;
  const loaOpt = type.loaOptions?.find((o) => o.value === loaValue);
  const loaCustom = !!type.loaOptions && !!loaValue && !loaOpt;
  const loaBand = loaBandOf(type, loaValue);

  return (
    <div>
      <div className="hx-wizard__head hx-wizard__head--tight">
        <ProviderLogo kind={type.kind} size={36} />
        <div>
          <strong className="hx-wizard__head-title">{displayName}</strong>
          <div className="hx-wizard__head-meta">
            <span className="hx-wizard__head-proto">{type.protocol.toUpperCase()}</span>
            {loaCustom ? <Badge tone="neutral">LoA · {loaValue}</Badge> : loaBand && <LoaBadge level={loaBand} label={loaOpt?.label} />}
          </div>
        </div>
      </div>

      <div className="hx-wizard__kvlist">
        {row("Alias", alias)}
        {Object.entries(config)
          .filter(([k]) => k !== "metadataXml")
          .map(([k, v]) =>
            k === "minimumLoa"
              ? row("minimumLoa", loaOpt?.label ?? v)
              : k === "metadataFileName"
                ? row("Metadata XML", `${v} (${(config.metadataXml?.length ?? 0) > 0 ? `${(config.metadataXml!.length / 1024).toFixed(1)} KB` : "uploaded"})`)
                : row(k, /secret|pw|credential/i.test(k) ? secret(v) : v || "—")
          )}
        {row("Mappers", mappers.map((m) => `${m.source} → ${m.target}`).join(", ") || "—")}
      </div>

      <div className="hx-wizard__enable">
        <Switch checked={enabled} onChange={setEnabled} label="Enable immediately after creation" />
      </div>
    </div>
  );
}
