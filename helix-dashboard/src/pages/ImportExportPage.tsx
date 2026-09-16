/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Alert } from "../components/Alert";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { FormField, Textarea, Select } from "../components/FormField";
import { RealmIoApi, RealmExportDocument, RealmImportResult, OnConflict } from "../api/realmIo";
import { useT } from "../i18n/LocaleContext";

export interface ImportExportPageProps {
  api: RealmIoApi;
  realmId: string;
}

interface Note {
  tone: ToastTone;
  title: string;
  message?: string;
}

/** Every slice the document can carry, in display order, with friendly labels (mirrors the backend's
 * RealmExportDocument / SLICE_* keys). */
const SLICES: { key: string; label: string }[] = [
  { key: "realm", label: "Realm settings" },
  { key: "applications", label: "Applications" },
  { key: "clients", label: "OIDC clients" },
  { key: "samlClients", label: "SAML relying parties" },
  { key: "roles", label: "Realm roles" },
  { key: "clientScopes", label: "Client scopes" },
  { key: "groups", label: "Groups" },
  { key: "users", label: "Users" },
  { key: "identityProviders", label: "Identity providers" },
  { key: "flows", label: "Authentication flows" },
  { key: "organizations", label: "Organizations" },
  { key: "adminRoles", label: "Admin roles" },
  { key: "webhooks", label: "Webhooks" },
  { key: "scimTargets", label: "SCIM targets" },
  { key: "workloadIdentity", label: "Workload identity" },
  { key: "messagingProviders", label: "Messaging providers" },
  { key: "messageTemplates", label: "Message templates" },
  { key: "clientProtocolMappers", label: "Protocol mappers" },
  { key: "clientRoles", label: "Client roles" },
  { key: "serviceAccountRoles", label: "Service-account roles" },
  { key: "resourceIndicators", label: "Resource indicators" },
  { key: "authorizationServices", label: "Authorization services" },
  { key: "agents", label: "Agents" },
];

/** The portable slices a Keycloak realm-export maps into, in display order. */
const KEYCLOAK_SLICES: { key: string; label: string }[] = [
  { key: "clients", label: "OIDC clients" },
  { key: "roles", label: "Realm roles" },
  { key: "identityProviders", label: "Identity providers" },
];

type ImportFormat = "helix" | "keycloak";

/** Counts the entries the parsed document carries for each slice (for the import preview). */
function previewCounts(doc: RealmExportDocument): { key: string; label: string; count: number }[] {
  return SLICES.map(({ key, label }) => {
    const value = doc[key];
    let count = 0;
    if (key === "realm") count = value ? 1 : 0;
    else if (Array.isArray(value)) count = value.length;
    return { key, label, count };
  });
}

/**
 * Counts the portable slices a Keycloak realm-export will translate into. Mirrors KeycloakImporter on the
 * backend: OIDC clients (SAML protocol skipped), realm roles (roles.realm[]), identity providers. Users,
 * SAML clients and realm settings are intentionally not imported.
 */
function previewKeycloakCounts(doc: RealmExportDocument): { key: string; label: string; count: number }[] {
  const clients = Array.isArray(doc.clients)
    ? (doc.clients as Array<Record<string, unknown>>).filter((c) => String(c?.protocol ?? "openid-connect").toLowerCase() !== "saml")
    : [];
  const realmRoles = (doc.roles as { realm?: unknown } | undefined)?.realm;
  const idps = doc.identityProviders;
  const byKey: Record<string, number> = {
    clients: clients.length,
    roles: Array.isArray(realmRoles) ? realmRoles.length : 0,
    identityProviders: Array.isArray(idps) ? idps.length : 0,
  };
  return KEYCLOAK_SLICES.map(({ key, label }) => ({ key, label, count: byKey[key] ?? 0 }));
}

/**
 * Helix IAM: the Import / export screen. Download a realm's full configuration as a single self-describing
 * JSON document (secrets masked server-side), or paste/drop one in to idempotently upsert it into this
 * realm — with a slice-count preview before confirming and a per-slice {created, updated, skipped} summary
 * after. Mirrors the ProvisioningPage layout/conventions.
 */
export function ImportExportPage({ api, realmId }: ImportExportPageProps) {
  const { t } = useT();
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);

  // Import workflow state.
  const [format, setFormat] = React.useState<ImportFormat>("helix");
  const [raw, setRaw] = React.useState("");
  const [parsed, setParsed] = React.useState<RealmExportDocument | null>(null);
  const [parseError, setParseError] = React.useState<string | null>(null);
  const [dragging, setDragging] = React.useState(false);
  const [onConflict, setOnConflict] = React.useState<OnConflict>("overwrite");
  const [result, setResult] = React.useState<RealmImportResult | null>(null);

  const onText = (text: string) => {
    setRaw(text);
    setResult(null);
    if (!text.trim()) {
      setParsed(null);
      setParseError(null);
      return;
    }
    try {
      const doc = JSON.parse(text) as RealmExportDocument;
      if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
        throw new Error("Document must be a JSON object.");
      }
      setParsed(doc);
      setParseError(null);
    } catch (e) {
      setParsed(null);
      setParseError(String((e as Error).message ?? e));
    }
  };

  const readFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => onText(String(reader.result ?? ""));
    reader.readAsText(file);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) readFile(file);
  };

  const exportRealm = async () => {
    setBusy(true);
    try {
      const doc = await api.exportRealm(realmId);
      const blob = new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${realmId}-realm-export.json`;
      a.click();
      URL.revokeObjectURL(url);
      setNote({ tone: "success", title: t("importExport.toast.exported"), message: t("importExport.toast.exportedMsg") });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("importExport.error.export"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const runImport = async () => {
    if (!parsed) return;
    setBusy(true);
    try {
      const summary = format === "keycloak"
        ? await api.importKeycloak(realmId, parsed)
        : await api.importRealm(realmId, parsed, onConflict);
      setResult(summary);
      const conflicts = (summary as { conflicts?: string[] }).conflicts;
      setNote(conflicts && conflicts.length
        ? { tone: "error", title: t("importExport.toast.conflicts"), message: `${conflicts.length} existing entr${conflicts.length === 1 ? "y" : "ies"}: ${conflicts.slice(0, 5).join(", ")}${conflicts.length > 5 ? "…" : ""}` }
        : { tone: "success", title: t("importExport.toast.imported"), message: t("importExport.toast.importedMsg", { realm: realmId }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("importExport.error.import"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const counts = parsed ? (format === "keycloak" ? previewKeycloakCounts(parsed) : previewCounts(parsed)) : [];

  return (
    <Page>
      <PageHeader
        title={t("importExport.title")}
        description={<>{t("importExport.desc.pre")} <strong>{realmId}</strong> {t("importExport.desc.post")}</>}
      />

      <PageBody>
        <div className="hx-detailgrid">
          <Section
            title={t("importExport.export.title")}
            description={t("importExport.export.desc")}
          >
            <div className="hx-toolbar">
              <Button variant="primary" onClick={exportRealm} disabled={busy}>{t("importExport.export.btn")}</Button>
            </div>
            <p className="hx-help">
              {t("importExport.export.help")}
            </p>
          </Section>

          <div className="hx-pagebody">
            <Section
              title={t("importExport.import.title")}
              description={format === "keycloak" ? t("importExport.import.desc.keycloak") : t("importExport.import.desc.helix")}
            >
              <div className="hx-pagebody">
                <div>
                  <div className="hx-seg" role="radiogroup" aria-label={t("importExport.import.source")}>
                    {([["helix", t("importExport.import.helixExport")], ["keycloak", t("importExport.import.keycloakExport")]] as [ImportFormat, string][]).map(([value, label]) => {
                      const active = format === value;
                      return (
                        <button
                          key={value}
                          type="button"
                          role="radio"
                          aria-checked={active}
                          onClick={() => { if (value !== format) { setFormat(value); onText(""); } }}
                          disabled={busy}
                          className={active ? "hx-seg__btn is-active" : "hx-seg__btn"}
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div
                  onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={onDrop}
                  className={`hx-dropzone${dragging ? " hx-dropzone--drag" : raw ? " hx-dropzone--has-file" : ""}`}
                >
                  <Textarea
                    className="hx-mono"
                    value={raw}
                    onChange={(e) => onText(e.target.value)}
                    placeholder={format === "keycloak" ? t("importExport.import.placeholder.keycloak") : t("importExport.import.placeholder.helix")}
                    spellCheck={false}
                  />
                </div>

                <div className="hx-inputrow">
                  <label className="hx-btn hx-btn--ghost">
                    {t("importExport.import.chooseFile")}
                    <input
                      type="file"
                      accept=".json,application/json"
                      hidden
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) readFile(file);
                        e.target.value = "";
                      }}
                    />
                  </label>
                  {raw && (
                    <Button variant="ghost" onClick={() => onText("")} disabled={busy}>{t("importExport.import.clear")}</Button>
                  )}
                </div>

                {parseError && (
                  <Alert tone="danger" title={t("importExport.import.invalidJson")}>{parseError}</Alert>
                )}
              </div>
            </Section>

            {parsed && (
              <Section title={t("importExport.preview.title")}>
                <div className="hx-pagebody">
                  <div className="hx-badges">
                    {counts.map(({ key, count }) => (
                      <Badge key={key} tone={count > 0 ? "accent" : "neutral"}>{t(`importExport.slice.${key}`)}: {count}</Badge>
                    ))}
                  </div>
                  {format === "helix" && (
                    <FormField label={t("importExport.preview.onConflict")}>
                      <Select
                        value={onConflict}
                        onChange={(v) => setOnConflict(v as OnConflict)}
                        disabled={busy}
                        options={[
                          { value: "overwrite", label: t("importExport.conflict.overwrite") },
                          { value: "skip", label: t("importExport.conflict.skip") },
                          { value: "fail", label: t("importExport.conflict.fail") },
                        ]}
                      />
                    </FormField>
                  )}
                  <div className="hx-formactions hx-formactions--end">
                    <Button variant="primary" onClick={runImport} disabled={busy}>
                      {busy ? t("importExport.import.btn.importing") : format === "keycloak" ? t("importExport.import.btn.migrate") : t("importExport.import.btn.import")}
                    </Button>
                  </div>
                </div>
              </Section>
            )}

            {result && (
              <Section title={t("importExport.result.title")}>
                <div className="hx-tablescroll">
                  <table className="hx-table">
                    <thead>
                      <tr><th>{t("importExport.th.slice")}</th><th className="hx-cell-right">{t("importExport.th.created")}</th><th className="hx-cell-right">{t("importExport.th.updated")}</th><th className="hx-cell-right">{t("importExport.th.skipped")}</th></tr>
                    </thead>
                    <tbody>
                      {SLICES.filter((s) => result.slices[s.key]).map(({ key }) => {
                        const s = result.slices[key];
                        return (
                          <tr key={key}>
                            <td>{t(`importExport.slice.${key}`)}</td>
                            <td className="hx-cell-right">{s.created}</td>
                            <td className="hx-cell-right">{s.updated}</td>
                            <td className="hx-cell-right">{s.skipped}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Section>
            )}
          </div>
        </div>

        {busy && !parsed && (
          <div className="hx-loadwrap"><Spinner size={22} label={t("importExport.working")} /></div>
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
