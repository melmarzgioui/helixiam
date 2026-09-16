/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { Switch } from "../components/Switch";
import { Checkbox } from "../components/Choice";
import { FormField, Input } from "../components/FormField";
import { CopyRow } from "../components/CopyRow";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { RowMenu } from "../components/RowMenu";
import { ProvisioningApi, ProvisioningConfig } from "../api/provisioning";
import { Modal, ConfirmDialog } from "../components/Modal";
import {
  ScimTargetApi, ScimTarget, ScimTargetWrite, validateScimTarget, SCIM_EVENT_OPTIONS, createScimTargetHttpClient,
} from "../api/scimTargets";
import { useT } from "../i18n/LocaleContext";

export interface ProvisioningPageProps {
  api: ProvisioningApi;
  realmId: string;
  /** B7: outbound SCIM targets client; defaults to the live HTTP client. */
  scimApi?: ScimTargetApi;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/**
 * E11: the Provisioning screen — SCIM 2.0 inbound provisioning and OIDC Dynamic Client Registration for
 * the realm. Issue/rotate/clear the SCIM bearer token (shown once, never re-readable), switch the DCR
 * policy between gated (default) and open, and mint DCR initial access tokens for gated registration.
 */
export function ProvisioningPage({ api, realmId, scimApi }: ProvisioningPageProps) {
  const { t } = useT();
  const scim = React.useMemo(() => scimApi ?? createScimTargetHttpClient(), [scimApi]);
  const [config, setConfig] = React.useState<ProvisioningConfig | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);
  const [revealedToken, setRevealedToken] = React.useState<string | null>(null);
  const [revealedIat, setRevealedIat] = React.useState<string | null>(null);

  const reload = React.useCallback(() => {
    setConfig(null);
    api.get(realmId).then(setConfig).catch((e) => {
      setNote({ tone: "error", title: t("provisioning.errLoad"), message: String(e.message ?? e) });
    });
  }, [api, realmId]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(reload, [reload]);

  const save = async (body: { dcrOpen: boolean | null; rotateScimToken: boolean; clearScimToken: boolean }) => {
    setBusy(true);
    try {
      const result = await api.save(realmId, body);
      setConfig(result.config);
      if (result.newScimToken) {
        setRevealedToken(result.newScimToken);
        setNote({ tone: "success", title: t("provisioning.toastScimTokenGenerated"), message: t("provisioning.toastScimTokenMsg") });
      } else {
        setNote({ tone: "success", title: t("provisioning.toastSaved") });
      }
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("provisioning.errSave"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const issueIat = async () => {
    setBusy(true);
    try {
      const result = await api.issueInitialAccessToken(realmId);
      setRevealedIat(result.initialAccessToken);
      setNote({ tone: "success", title: t("provisioning.toastIatMinted"), message: t("provisioning.toastIatMsg") });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("provisioning.errMintToken"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("provisioning.title")}
        description={<>{t("provisioning.descPre")} <strong>{realmId}</strong> {t("provisioning.descPost")}</>}
        actions={<Button variant="ghost" onClick={reload} disabled={busy}>{t("provisioning.refreshBtn")}</Button>}
      />

      <PageBody>
        {!config ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("common.loading")} /></div>
        ) : (
          <div className="hx-detailgrid">
            <Section title={t("provisioning.sectionScimTitle")} description={t("provisioning.sectionScimDesc")}>
              <div className="hx-clientgrid">
                <div className="hx-inputrow">
                  <span className="hx-muted">{t("provisioning.statusLabel")}</span>
                  {config.scimTokenSet
                    ? <Badge tone="accent">{t("provisioning.badgeConfigured")}</Badge>
                    : <Badge tone="neutral">{t("provisioning.badgeNotSet")}</Badge>}
                </div>
                {revealedToken && (
                  <div className="hx-colstack">
                    <CopyRow label={t("provisioning.scimTokenLabel")} value={revealedToken} />
                    <p className="hx-help">{t("provisioning.scimTokenShownOnce")}</p>
                  </div>
                )}
                <div className="hx-inputrow">
                  <Button variant="primary" onClick={() => save({ dcrOpen: null, rotateScimToken: true, clearScimToken: false })} disabled={busy}>
                    {config.scimTokenSet ? t("provisioning.rotateToken") : t("provisioning.generateToken")}
                  </Button>
                  {config.scimTokenSet && (
                    <Button variant="ghost" onClick={() => { setRevealedToken(null); save({ dcrOpen: null, rotateScimToken: false, clearScimToken: true }); }} disabled={busy}>
                      {t("provisioning.revokeBtn")}
                    </Button>
                  )}
                </div>
                <p className="hx-help">
                  {t("provisioning.scimBaseUrlLabel")} <code>/realms/{realmId}/scim/v2</code>
                </p>
              </div>
            </Section>

            <Section title={t("provisioning.sectionDcrTitle")} description={t("provisioning.sectionDcrDesc")}>
              <div className="hx-clientgrid">
                <div className="hx-colstack">
                  <Switch
                    label={t("provisioning.dcrOpenLabel")}
                    checked={config.dcrOpen}
                    onChange={(v) => save({ dcrOpen: v, rotateScimToken: false, clearScimToken: false })}
                  />
                  <span className="hx-help">{t("provisioning.dcrOpenHint")}</span>
                </div>
                <div className="hx-inputrow">
                  <span className="hx-muted">{t("provisioning.policyLabel")}</span>
                  {config.dcrOpen ? <Badge tone="warning">{t("provisioning.badgeOpen")}</Badge> : <Badge tone="accent">{t("provisioning.badgeGated")}</Badge>}
                </div>
                {!config.dcrOpen && (
                  <>
                    <div className="hx-inputrow">
                      <Button variant="ghost" onClick={issueIat} disabled={busy}>{t("provisioning.mintIatBtn")}</Button>
                    </div>
                    {revealedIat && (
                      <div className="hx-colstack">
                        <CopyRow label={t("provisioning.iatLabel")} value={revealedIat} />
                        <p className="hx-help">{t("provisioning.iatHint", { realm: realmId })}</p>
                      </div>
                    )}
                  </>
                )}
                <p className="hx-help">
                  {t("provisioning.registrationEndpointLabel")} <code>/realms/{realmId}/connect/register</code>
                </p>
              </div>
            </Section>
          </div>
        )}

        {/* B7: outbound SCIM provisioning — push local user lifecycle to downstream service providers. */}
        <OutboundScimSection scim={scim} realmId={realmId} onNote={setNote} />
      </PageBody>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

/**
 * B7: per-realm outbound SCIM 2.0 targets. Each target receives create/update/disable/delete of local
 * users as SCIM operations (the auth server as a SCIM client). The bearer token is write-only.
 */
function OutboundScimSection({ scim, realmId, onNote }: {
  scim: ScimTargetApi; realmId: string; onNote: (n: Note) => void;
}) {
  const { t } = useT();
  const [targets, setTargets] = React.useState<ScimTarget[] | null>(null);
  const [editing, setEditing] = React.useState<ScimTarget | "new" | null>(null);
  const [toDelete, setToDelete] = React.useState<ScimTarget | null>(null);

  const reload = React.useCallback(() => {
    setTargets(null);
    scim.list(realmId).then(setTargets)
      .catch((e) => { setTargets([]); onNote({ tone: "error", title: t("provisioning.errLoadTargets"), message: String(e.message ?? e) }); });
  }, [scim, realmId, onNote]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(reload, [reload]);

  const confirmDelete = async () => {
    const tgt = toDelete; setToDelete(null);
    if (!tgt) return;
    try {
      await scim.remove(realmId, tgt.id);
      onNote({ tone: "info", title: t("provisioning.toastTargetRemoved") });
      reload();
    } catch (e: unknown) {
      onNote({ tone: "error", title: t("provisioning.errRemoveTarget"), message: String((e as Error).message ?? e) });
    }
  };

  const save = async (body: ScimTargetWrite) => {
    try {
      if (editing === "new") await scim.create(realmId, body);
      else if (editing) await scim.update(realmId, editing.id, body);
      setEditing(null);
      onNote({ tone: "success", title: t("provisioning.toastTargetSaved"), message: t("provisioning.toastTargetSavedMsg") });
      reload();
    } catch (e: unknown) {
      onNote({ tone: "error", title: t("provisioning.errSaveTarget"), message: String((e as Error).message ?? e) });
    }
  };

  const targetName = (target: ScimTarget) => target.name?.trim() || t("provisioning.unnamedTarget");
  const menuItems = (target: ScimTarget) => [
    { label: t("common.edit"), onSelect: () => setEditing(target) },
    { label: t("provisioning.menuRemove"), danger: true, onSelect: () => setToDelete(target) },
  ];
  const targetBadges = (target: ScimTarget) => (
    <span className="hx-badges">
      {target.enabled ? <Badge tone="accent">{t("provisioning.badgeEnabled")}</Badge> : <Badge tone="neutral">{t("provisioning.badgeDisabled")}</Badge>}
      {target.tokenSet ? <Badge tone="success">{t("provisioning.badgeTokenSet")}</Badge> : <Badge tone="warning">{t("provisioning.badgeNoToken")}</Badge>}
    </span>
  );
  const targetEvents = (target: ScimTarget) => (target.eventTypes?.trim() ? target.eventTypes : t("provisioning.allUserEvents"));

  return (
    <>
      <Section
        title={t("provisioning.sectionOutboundTitle")}
        description={t("provisioning.sectionOutboundDesc")}
        actions={<Button variant="primary" onClick={() => setEditing("new")}>{t("provisioning.addTargetBtn")}</Button>}
      >
        {targets === null ? (
          <div className="hx-loadwrap"><Spinner size={22} label={t("common.loading")} /></div>
        ) : targets.length === 0 ? (
          <EmptyState
            title={t("provisioning.emptyOutboundTitle")}
            message={t("provisioning.emptyOutboundMsg")}
            action={<Button variant="primary" onClick={() => setEditing("new")}>{t("provisioning.addTargetBtn")}</Button>}
          />
        ) : (
          <>
            {/* desktop table */}
            <div className="hx-tablescroll hx-show-desktop">
              <table className="hx-table">
                <thead>
                  <tr>
                    <th>{t("provisioning.colTarget")}</th>
                    <th>{t("provisioning.colEndpoint")}</th>
                    <th>{t("provisioning.colEvents")}</th>
                    <th className="hx-col-actions" aria-label={t("provisioning.actionsLabel")} />
                  </tr>
                </thead>
                <tbody>
                  {targets.map((tgt) => (
                    <tr key={tgt.id}>
                      <td>
                        <div className="hx-namecell">
                          <button type="button" className="hx-textbtn" onClick={() => setEditing(tgt)}>{targetName(tgt)}</button>
                          {targetBadges(tgt)}
                        </div>
                      </td>
                      <td><span className="hx-mono hx-muted">{tgt.baseUrl}</span></td>
                      <td className="hx-faint">{targetEvents(tgt)}</td>
                      <td className="hx-cell-right">
                        <RowMenu items={menuItems(tgt)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* mobile cards */}
            <div className="hx-cards hx-show-mobile">
              {targets.map((tgt) => (
                <div className="hx-rowcard" key={tgt.id}>
                  <div className="hx-rowcard__head">
                    <div className="hx-rowcard__grow">
                      <div className="hx-rowcard__title hx-namecell">
                        <button type="button" className="hx-textbtn" onClick={() => setEditing(tgt)}>{targetName(tgt)}</button>
                        {targetBadges(tgt)}
                      </div>
                      <div className="hx-rowcard__sub hx-mono">{tgt.baseUrl}</div>
                      <div className="hx-rowcard__sub">{targetEvents(tgt)}</div>
                    </div>
                    <div className="hx-rowcard__actions">
                      <RowMenu items={menuItems(tgt)} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </Section>

      <Modal open={editing !== null} title={editing === "new" ? t("provisioning.modalAddTitle") : t("provisioning.modalEditTitle")} onClose={() => setEditing(null)} width={520}>
        {editing !== null && (
          <ScimTargetForm initial={editing === "new" ? null : editing} onSubmit={save} onCancel={() => setEditing(null)} />
        )}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("provisioning.confirmRemoveTitle")}
        message={t("provisioning.confirmRemoveMsg", { name: toDelete?.name?.trim() || toDelete?.baseUrl || "" })}
        confirmLabel={t("provisioning.confirmRemoveLabel")}
        onConfirm={confirmDelete}
        onCancel={() => setToDelete(null)}
      />
    </>
  );
}

/** Add/edit form for one outbound SCIM target. The bearer token is write-only (blank on edit keeps it). */
function ScimTargetForm({ initial, onSubmit, onCancel }: {
  initial: ScimTarget | null; onSubmit: (b: ScimTargetWrite) => void; onCancel: () => void;
}) {
  const { t } = useT();
  const [name, setName] = React.useState(initial?.name ?? "");
  const [baseUrl, setBaseUrl] = React.useState(initial?.baseUrl ?? "");
  const [token, setToken] = React.useState("");
  const [enabled, setEnabled] = React.useState(initial?.enabled ?? true);
  const [events, setEvents] = React.useState<string[]>(
    (initial?.eventTypes ?? "").split(",").map((s) => s.trim()).filter(Boolean));
  const [attempted, setAttempted] = React.useState(false);

  const body: ScimTargetWrite = { name: name.trim() || null, baseUrl: baseUrl.trim(), token: token.trim() || undefined, eventTypes: events.join(","), enabled };
  const missing = validateScimTarget(body);

  const toggleEvent = (key: string) =>
    setEvents((prev) => prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]);

  const submit = () => {
    if (missing.length) { setAttempted(true); return; }
    onSubmit(body);
  };

  return (
    <div>
      <FormField label={t("provisioning.fieldName")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Slack" />
      </FormField>
      <FormField label={t("provisioning.fieldScimBaseUrl")} required error={attempted && missing.includes("baseUrl") ? t("provisioning.errBaseUrlRequired") : undefined}>
        <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://api.example.com/scim/v2" />
      </FormField>
      <FormField label={t("provisioning.fieldBearerToken")}>
        <Input type="password" value={token} onChange={(e) => setToken(e.target.value)}
               placeholder={initial?.tokenSet ? t("provisioning.tokenPlaceholderKeep") : t("provisioning.tokenPlaceholderNew")} autoComplete="new-password" />
      </FormField>
      <FormField label={t("provisioning.fieldSyncEvents")} hint={t("provisioning.fieldSyncEventsHint")}>
        <div className="hx-colstack">
          {SCIM_EVENT_OPTIONS.map((o) => (
            <Checkbox
              key={o.key}
              checked={events.includes(o.key)}
              onChange={() => toggleEvent(o.key)}
              label={<span>{o.label} <code className="hx-faint hx-mono">{o.key}</code></span>}
            />
          ))}
        </div>
      </FormField>
      <div className="hx-field">
        <Checkbox label={t("provisioning.fieldEnabled")} checked={enabled} onChange={setEnabled} />
      </div>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={submit}>{t("provisioning.saveTargetBtn")}</Button>
      </div>
    </div>
  );
}
