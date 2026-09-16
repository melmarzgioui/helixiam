import React from "react";
import { Stepper } from "./Stepper";
import { Button } from "./Button";
import { FormField, Input } from "./FormField";
import { Select } from "./Select";
import { Checkbox } from "./Choice";
import { Switch } from "./Switch";
import { Divider } from "./Divider";
import { ProviderLogo } from "./ProviderLogo";
import { ProviderTile } from "./ProviderTile";
import { LoaBadge } from "./LoaBadge";
import { Badge } from "./Badge";
import { MetadataUpload } from "./MetadataUpload";
import { PROVIDER_TYPES, DEFAULT_MAPPERS, findProviderType, loaBandOf, missingConnectionFields, ProviderType, AttributeMapper } from "./providerCatalog";

const STEPS = ["Provider", "Connection", "Mappers", "Review"];

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
export function ProviderWizard({ onComplete, onCancel, initial }: ProviderWizardProps) {
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

  const pickType = (t: ProviderType) => {
    setTypeId(t.id);
    setAlias(t.id);
    setDisplayName(t.name);
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
    if (step === 1) {
      if (missing.length) { setAttempted(true); return; } // block + reveal errors
    }
    if (step < STEPS.length - 1) { setAttempted(false); setStep(step + 1); }
    else if (type) onComplete?.({ providerType: type.id, alias, displayName, config, mappers: builtMappers(), enabled });
  };
  const back = () => { setAttempted(false); step > firstStep ? setStep(step - 1) : onCancel?.(); };

  return (
    <div style={{ maxWidth: 640 }}>
      <div style={{ marginBottom: "1.6rem" }}>
        <Stepper steps={STEPS} current={step} />
      </div>

      {step === 0 && (
        <div style={{ display: "grid", gap: ".7rem" }}>
          {PROVIDER_TYPES.map((t) => (
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

      {step === 1 && type && (
        <ConnectionForm type={type} alias={alias} setAlias={setAlias} displayName={displayName} setDisplayName={setDisplayName} config={config} set={set} unset={unset} lockAlias={editing} errors={attempted ? missing : []} />
      )}

      {step === 2 && type && (
        <MappersStep
          type={type}
          presetSources={presetSources}
          togglePreset={togglePreset}
          customMappers={customMappers}
          setCustomMappers={setCustomMappers}
        />
      )}

      {step === 3 && type && (
        <ReviewStep type={type} alias={alias} displayName={displayName} config={config} mappers={builtMappers()} enabled={enabled} setEnabled={setEnabled} />
      )}

      <Divider gap="1.5rem" />
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <Button variant="ghost" onClick={back}>{step === firstStep ? "Cancel" : "Back"}</Button>
        <Button variant="primary" onClick={next} disabled={!canNext}>
          {step === STEPS.length - 1 ? (editing ? "Save changes" : "Create connection") : "Continue"}
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
      <div style={{ display: "flex", alignItems: "center", gap: ".7rem", marginBottom: "1.1rem" }}>
        <ProviderLogo kind={type.kind} size={32} />
        <strong style={{ font: "600 1.05rem var(--font)" }}>{type.name}</strong>
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
            <div style={{ marginBottom: "1rem" }}>
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
                  style={{ marginTop: ".55rem" }}
                  value={config.minimumLoa ?? ""}
                  onChange={(e) => set("minimumLoa", e.target.value)}
                  aria-label="Custom level of assurance"
                  placeholder="urn:nl-eid-gdi:1.0:LoA:…"
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
      <p style={{ marginTop: 0, color: "var(--fg-muted)" }}>
        Map {type.protocol.toUpperCase()} attributes onto the user profile. Tick the common ones, or add your own.
      </p>

      <div style={{ display: "flex", flexDirection: "column", gap: ".7rem" }}>
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
        <div style={{ marginTop: "1.1rem", display: "flex", flexDirection: "column", gap: ".55rem" }}>
          <span style={{ fontWeight: 600, fontSize: ".9rem", color: "var(--fg)" }}>Custom attributes</span>
          {customMappers.map((m, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: ".5rem" }}>
              <Input
                value={m.source}
                onChange={(e) => editCustom(i, { source: e.target.value })}
                aria-label={`Custom attribute ${i + 1} source`}
                placeholder="IdP attribute (e.g. department)"
              />
              <span aria-hidden="true" style={{ color: "var(--fg-faint)", flexShrink: 0 }}>→</span>
              <Input
                value={m.target}
                onChange={(e) => editCustom(i, { target: e.target.value })}
                aria-label={`Custom attribute ${i + 1} target`}
                placeholder="user attribute"
              />
              <button
                type="button"
                className="hx-ghosticon"
                style={{ width: 36, height: 36, flexShrink: 0 }}
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

      <div style={{ marginTop: ".9rem" }}>
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
    <div key={k} style={{ display: "flex", justifyContent: "space-between", gap: "1rem", padding: ".4rem 0", borderBottom: "1px solid var(--border)" }}>
      <span style={{ color: "var(--fg-faint)" }}>{k}</span>
      <span style={{ color: "var(--fg)", textAlign: "right", wordBreak: "break-all" }}>{v}</span>
    </div>
  );
  const secret = (v?: string) => (v ? "••••••••" : "—");
  const loaValue = config.minimumLoa ?? type.defaultLoaValue;
  const loaOpt = type.loaOptions?.find((o) => o.value === loaValue);
  const loaCustom = !!type.loaOptions && !!loaValue && !loaOpt;
  const loaBand = loaBandOf(type, loaValue);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: ".7rem", marginBottom: "1rem" }}>
        <ProviderLogo kind={type.kind} size={36} />
        <div>
          <strong style={{ font: "600 1.05rem var(--font)" }}>{displayName}</strong>
          <div style={{ display: "flex", gap: ".4rem", marginTop: ".25rem" }}>
            <span style={{ fontSize: ".82rem", color: "var(--fg-muted)" }}>{type.protocol.toUpperCase()}</span>
            {loaCustom ? <Badge tone="neutral">LoA · {loaValue}</Badge> : loaBand && <LoaBadge level={loaBand} label={loaOpt?.label} />}
          </div>
        </div>
      </div>

      <div style={{ font: "400 .9rem var(--font)" }}>
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

      <div style={{ marginTop: "1.1rem" }}>
        <Switch checked={enabled} onChange={setEnabled} label="Enable immediately after creation" />
      </div>
    </div>
  );
}
