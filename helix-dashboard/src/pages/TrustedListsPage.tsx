/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Alert } from "../components/Alert";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { Checkbox } from "../components/Choice";
import { Detail, DetailList } from "../components/DetailList";
import { EmptyState } from "../components/EmptyState";
import { FormField, Input, Textarea } from "../components/FormField";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Select } from "../components/Select";
import { Spinner } from "../components/Spinner";
import { Switch } from "../components/Switch";
import { Table, type Column } from "../components/Table";
import { useToast } from "../components/ToastProvider";
import { AdminApiError } from "../api/adminError";
import { absoluteTime } from "../api/datetime";
import type { TrustedList, TrustedListAnchor, TrustedListApi } from "../api/trustedLists";
import { useT } from "../i18n/LocaleContext";
import { commonName, expiryState } from "./walletProvider";
import {
  DEFAULT_TRUSTED_LIST_FORM, GRACE_RANGE, STATUS_OPTIONS, TRUSTED_LIST_PRESETS, applyPreset, formFromTrustedList,
  statusTone, trustedListWrite, validateTrustedList, type TrustedListForm,
} from "./trustedList";

// Federation → Trusted lists: the realm's published, signed lists (ETSI TS 119 612 / 119 602) whose verified service
// certificates become EUDI wallet trust anchors. The list shows every source and its health; a source's page shows
// the last refresh, the anchors it yields and its settings, and refreshes it on demand. State and rules live in
// trustedList.ts; this file only renders them.

export interface TrustedListsPageProps {
  api: TrustedListApi;
  realmId: string;
  onOpen: (id: string) => void;
}

/** A certificate's expiry as a date only ("27 Nov 2032"). */
const absoluteDate = (iso: string, locale: "en" | "nl") => {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return new Intl.DateTimeFormat(locale === "nl" ? "nl-NL" : "en-GB", { dateStyle: "medium" }).format(d);
};

const hostOf = (url: string) => {
  try { return new URL(url).host; } catch { return url; }
};

function StatusBadge({ list }: { list: TrustedList }) {
  const { t } = useT();
  return <Badge tone={statusTone(list.status)}>{t(`tl.status.${list.status}`)}</Badge>;
}

export function TrustedListsPage({ api, realmId, onOpen }: TrustedListsPageProps) {
  const { t, locale } = useT();
  const toast = useToast();
  const [rows, setRows] = React.useState<TrustedList[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [creating, setCreating] = React.useState(false);

  const reload = React.useCallback(() => {
    setError(null);
    api.list(realmId).then(setRows).catch((e: unknown) => { setRows([]); setError(String((e as Error).message ?? e)); });
  }, [api, realmId]);
  React.useEffect(() => { setRows(null); reload(); }, [reload]);

  const columns: Column<TrustedList>[] = [
    { key: "name", header: t("tl.th.name"), render: (l) => (
      <span className="hx-namecell">
        <button type="button" className="hx-textbtn" onClick={() => onOpen(l.id)}>{l.name}</button>
        {!l.enabled && <Badge tone="neutral">{t("tl.disabled")}</Badge>}
      </span>
    ) },
    { key: "source", header: t("tl.th.source"), render: (l) => (
      <span className="hx-stack-tight">
        <span className="hx-mono hx-muted">{hostOf(l.url)}</span>
        <span className="hx-faint">{t(`tl.format.${l.format}`)}</span>
      </span>
    ) },
    { key: "status", header: t("tl.th.status"), render: (l) => <StatusBadge list={l} /> },
    { key: "anchors", header: t("tl.th.anchors"), align: "right", render: (l) => String(l.anchorCount) },
    { key: "nextUpdate", header: t("tl.th.nextUpdate"), render: (l) => absoluteTime(l.nextUpdate, locale) },
    { key: "lastRefresh", header: t("tl.th.lastRefresh"), render: (l) => absoluteTime(l.lastAttemptAt, locale) },
  ];

  return (
    <Page>
      <PageHeader
        title={t("tl.title")}
        description={t("tl.desc")}
        actions={<Button variant="primary" onClick={() => setCreating(true)}>{t("tl.action.new")}</Button>}
      />
      <PageBody>
        {error && <Alert tone="danger" title={t("tl.error.load")}>{error}</Alert>}
        {rows === null ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("tl.loading")} /></div>
        ) : rows.length === 0 ? (
          <EmptyState title={t("tl.empty.title")} message={t("tl.empty.message")}
            action={<Button variant="primary" onClick={() => setCreating(true)}>{t("tl.action.new")}</Button>} />
        ) : (
          <>
            <div className="hx-show-desktop">
              <Table columns={columns} rows={rows} rowKey={(l) => l.id} onRowClick={(l) => onOpen(l.id)} />
            </div>
            <div className="hx-cards hx-show-mobile">
              {rows.map((l) => (
                <div className="hx-rowcard" key={l.id}>
                  <div className="hx-rowcard__head">
                    <div className="hx-rowcard__grow">
                      <div className="hx-rowcard__title hx-namecell">
                        <button type="button" className="hx-textbtn" onClick={() => onOpen(l.id)}>{l.name}</button>
                        <span className="hx-badges"><StatusBadge list={l} /></span>
                      </div>
                      <div className="hx-rowcard__sub hx-mono">{hostOf(l.url)}</div>
                      <div className="hx-rowcard__sub">
                        {`${t("tl.anchorCount", { n: l.anchorCount })} · ${t("tl.th.nextUpdate")}: ${absoluteTime(l.nextUpdate, locale)}`}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
        <Section title={t("tl.about.title")} description={t("tl.about.desc")}>
          <ul className="hx-bullets">
            <li>{t("tl.about.eudiTest")}</li>
            <li>{t("tl.about.ecLote")}</li>
            <li>{t("tl.about.euLotl")}</li>
            <li>{t("tl.about.failSafe")}</li>
          </ul>
        </Section>
      </PageBody>

      <Modal open={creating} title={t("tl.modal.new")} onClose={() => setCreating(false)} width={640}>
        {creating && (
          <TrustedListEditor withPresets submitLabel={t("tl.form.create")} onCancel={() => setCreating(false)}
            onSubmit={async (form) => {
              const created = await api.create(realmId, trustedListWrite(form));
              setCreating(false);
              toast.show({ tone: "success", title: t("tl.toast.created"), message: t("tl.toast.createdMsg") });
              onOpen(created.id);
            }} />
        )}
      </Modal>
    </Page>
  );
}

// ---------------------------------------------------------------------------------------------------- detail

export interface TrustedListDetailPageProps {
  api: TrustedListApi;
  realmId: string;
  id: string;
  onBack: () => void;
}

export function TrustedListDetailPage({ api, realmId, id, onBack }: TrustedListDetailPageProps) {
  const { t, locale } = useT();
  const toast = useToast();
  const [list, setList] = React.useState<TrustedList | null>(null);
  const [anchors, setAnchors] = React.useState<TrustedListAnchor[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [refreshing, setRefreshing] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);

  const load = React.useCallback(async () => {
    setError(null);
    try {
      const [l, a] = await Promise.all([api.get(realmId, id), api.anchors(realmId, id)]);
      setList(l);
      setAnchors(a);
    } catch (e: unknown) {
      setError(String((e as Error).message ?? e));
    }
  }, [api, realmId, id]);
  React.useEffect(() => { void load(); }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    try {
      const l = await api.refresh(realmId, id);
      setList(l);
      setAnchors(await api.anchors(realmId, id));
      toast.show(l.lastError
        ? { tone: "error", title: t("tl.toast.refreshFailed"), message: l.lastError }
        : { tone: "success", title: t("tl.toast.refreshed"), message: t("tl.anchorCount", { n: l.anchorCount }) });
    } catch (e: unknown) {
      toast.show({ tone: "error", title: t("tl.toast.refreshFailed"),
        message: e instanceof AdminApiError && e.status === 409 ? t("tl.busy") : String((e as Error).message ?? e) });
    } finally {
      setRefreshing(false);
    }
  };

  const remove = async () => {
    setDeleting(false);
    try {
      await api.remove(realmId, id);
      toast.show({ tone: "success", title: t("tl.toast.deleted") });
      onBack();
    } catch (e: unknown) {
      toast.show({ tone: "error", title: t("tl.error.delete"), message: String((e as Error).message ?? e) });
    }
  };

  if (error && !list) {
    return (
      <Page>
        <PageHeader title={t("tl.title")} actions={<Button variant="ghost" onClick={onBack}>{t("tl.back")}</Button>} />
        <PageBody><Alert tone="danger" title={t("tl.error.load")}>{error}</Alert></PageBody>
      </Page>
    );
  }
  if (!list) {
    return <Page><PageBody><div className="hx-loadwrap"><Spinner size={28} label={t("tl.loading")} /></div></PageBody></Page>;
  }

  const anchorColumns: Column<TrustedListAnchor>[] = [
    { key: "subject", header: t("tl.anchor.subject"), render: (a) => (
      <span className="hx-stack-tight">
        <strong>{commonName(a.subject)}</strong>
        <span className="hx-faint">{[a.serviceName, a.provider].filter(Boolean).join(" · ")}</span>
      </span>
    ) },
    { key: "issuer", header: t("tl.anchor.issuer"), render: (a) => commonName(a.issuer) },
    { key: "country", header: t("tl.anchor.country"), render: (a) => a.country ?? "—" },
    { key: "expiry", header: t("tl.anchor.expiry"), render: (a) => (
      <span className="hx-badges">{absoluteDate(a.notAfter, locale)}
        {expiryState(a.notAfter) === "expired" && <Badge tone="danger">{t("wallet.key.expired")}</Badge>}
      </span>
    ) },
    { key: "usable", header: t("tl.anchor.use"), render: (a) => a.usable
      ? <Badge tone="success">{t("tl.anchor.usable")}</Badge>
      : <Badge tone="neutral">{t("tl.anchor.notCa")}</Badge> },
  ];

  return (
    <Page>
      <PageHeader
        title={list.name}
        description={<span className="hx-wrap-anywhere">{list.url}</span>}
        actions={
          <span className="hx-inlineactions">
            <Button variant="ghost" onClick={onBack}>{t("tl.back")}</Button>
            <Button variant="primary" onClick={refresh} disabled={refreshing || !list.enabled}>
              {refreshing ? t("tl.refreshing") : t("tl.refresh")}
            </Button>
          </span>
        }
      />
      <PageBody>
        <Section title={t("tl.status.title")} description={t("tl.status.desc")}
          actions={<StatusBadge list={list} />}>
          <div className="hx-formblock">
          <StatusAlert list={list} />
          {list.lastError && (
            <Alert tone={list.anchorsInUse ? "warning" : "danger"} title={t("tl.lastError")}>
              <span className="hx-mono">{list.lastError}</span>
            </Alert>
          )}
          <DetailList>
            <Detail label={t("tl.d.anchors")} center>
              <span className="hx-badges">
                {t("tl.anchorCount", { n: list.anchorCount })}
                <Badge tone={list.anchorsInUse ? "success" : "neutral"}>{list.anchorsInUse ? t("tl.inUse") : t("tl.notInUse")}</Badge>
              </span>
            </Detail>
            <Detail label={t("tl.d.lastRefresh")} sub={list.lastSuccessAt ? `${t("tl.d.lastSuccess")} ${absoluteTime(list.lastSuccessAt, locale)}` : undefined}>
              {absoluteTime(list.lastAttemptAt, locale)}
            </Detail>
            <Detail label={t("tl.d.nextUpdate")} sub={list.anchorsUsableUntil ? `${t("tl.d.usableUntil")} ${absoluteTime(list.anchorsUsableUntil, locale)}` : undefined}>
              {absoluteTime(list.nextUpdate, locale)}
            </Detail>
            <Detail label={t("tl.d.nextRefresh")}>{absoluteTime(list.nextRefreshAt, locale)}</Detail>
            <Detail label={t("tl.d.issued")} sub={list.sequenceNumber !== null ? `${t("tl.d.sequence")} ${list.sequenceNumber}` : undefined}>
              {absoluteTime(list.listIssuedAt, locale)}
            </Detail>
            <Detail label={t("tl.d.lists")}>{list.listsRead === null ? "—" : t("tl.d.listsValue", { n: list.listsRead, services: list.serviceCount })}</Detail>
          </DetailList>
          </div>
        </Section>

        <Section title={t("tl.anchors.title")} description={t("tl.anchors.desc")}
          actions={<Badge tone="neutral">{t("tl.anchorCount", { n: anchors?.filter((a) => a.usable).length ?? 0 })}</Badge>}>
          {anchors === null ? <div className="hx-loadwrap"><Spinner size={24} label={t("tl.loading")} /></div>
            : anchors.length === 0 ? <EmptyState title={t("tl.anchors.emptyTitle")} message={t("tl.anchors.empty")} />
              : (
                <>
                  <div className="hx-show-desktop">
                    <Table columns={anchorColumns} rows={anchors} rowKey={(a) => `${a.serialNumber}-${a.subject}-${a.serviceType}`} />
                  </div>
                  <ul className="hx-certlist hx-show-mobile">
                    {anchors.map((a) => (
                      <li key={`${a.serialNumber}-${a.subject}-${a.serviceType}`} className="hx-certlist__item">
                        <div className="hx-certlist__head">
                          <strong>{commonName(a.subject)}</strong>
                          {a.usable ? <Badge tone="success">{t("tl.anchor.usable")}</Badge> : <Badge tone="neutral">{t("tl.anchor.notCa")}</Badge>}
                        </div>
                        <div className="hx-certlist__meta">
                          <span>{t("tl.anchor.issuer")}: {commonName(a.issuer)}</span>
                          <span>{t("tl.anchor.expiry")}: {absoluteDate(a.notAfter, locale)}</span>
                          <span>{[a.provider, a.country].filter(Boolean).join(" · ")}</span>
                        </div>
                      </li>
                    ))}
                  </ul>
                </>
              )}
        </Section>

        <Section title={t("tl.settings.title")} description={t("tl.settings.desc")}
          actions={<Button variant="danger" onClick={() => setDeleting(true)}>{t("tl.delete")}</Button>}>
          <TrustedListEditor key={`${list.id}-${list.name}-${list.url}`} initial={formFromTrustedList(list)} signers={list}
            submitLabel={t("tl.form.save")}
            onSubmit={async (form) => {
              const saved = await api.update(realmId, id, trustedListWrite(form));
              setList(saved);
              setAnchors(await api.anchors(realmId, id));
              toast.show({ tone: "success", title: t("tl.toast.saved") });
            }} />
        </Section>
      </PageBody>

      <ConfirmDialog open={deleting} title={t("tl.confirm.title")} message={t("tl.confirm.message", { name: list.name })}
        confirmLabel={t("tl.delete")} cancelLabel={t("common.cancel")} onConfirm={remove} onCancel={() => setDeleting(false)} />
    </Page>
  );
}

function StatusAlert({ list }: { list: TrustedList }) {
  const { t } = useT();
  switch (list.status) {
    case "NEVER": return <Alert tone="info" title={t("tl.alert.never.title")}>{t("tl.alert.never")}</Alert>;
    case "STALE": return <Alert tone="warning" title={t("tl.alert.stale.title")}>{t("tl.alert.stale")}</Alert>;
    case "EXPIRED": return <Alert tone="danger" title={t("tl.alert.expired.title")}>{t("tl.alert.expired")}</Alert>;
    case "ERROR": return <Alert tone="danger" title={t("tl.alert.error.title")}>{t("tl.alert.error")}</Alert>;
    case "DISABLED": return <Alert tone="info" title={t("tl.alert.disabled.title")}>{t("tl.alert.disabled")}</Alert>;
    default: return null;
  }
}

// ---------------------------------------------------------------------------------------------------- editor

interface EditorProps {
  initial?: TrustedListForm;
  withPresets?: boolean;
  /** The stored source, for the parsed signer certificates. */
  signers?: TrustedList;
  submitLabel: string;
  onSubmit: (form: TrustedListForm) => Promise<void>;
  onCancel?: () => void;
}

/** The settings form (create and edit). Validates before sending; the server's 400 lands on the same fields. */
function TrustedListEditor({ initial, withPresets, signers, submitLabel, onSubmit, onCancel }: EditorProps) {
  const { t, locale } = useT();
  const [form, setForm] = React.useState<TrustedListForm>(initial ?? DEFAULT_TRUSTED_LIST_FORM);
  const [attempted, setAttempted] = React.useState(false);
  const [serverErrors, setServerErrors] = React.useState<Record<string, string>>({});
  const [other, setOther] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [preset, setPreset] = React.useState("");
  const local = validateTrustedList(form);
  const errors = attempted ? { ...serverErrors, ...local } : serverErrors;
  const fe = (field: string) => (errors[field] ? t(errors[field]) : undefined);
  const set = (patch: Partial<TrustedListForm>) => {
    setForm((f) => ({ ...f, ...patch }));
    setServerErrors((e) => Object.fromEntries(Object.entries(e).filter(([k]) => !(k in patch))));
  };

  const submit = async () => {
    setAttempted(true);
    setOther(null);
    if (Object.keys(local).length) return;
    setBusy(true);
    try {
      await onSubmit(form);
      setAttempted(false);
    } catch (e: unknown) {
      if (e instanceof AdminApiError && Object.keys(e.fieldErrors).length) {
        setServerErrors(e.fieldErrors);
      } else {
        setOther(String((e as Error).message ?? e));
      }
    } finally {
      setBusy(false);
    }
  };

  const toggleStatus = (value: string, on: boolean) =>
    set({ acceptedStatuses: on ? [...form.acceptedStatuses.filter((s) => s !== value), value] : form.acceptedStatuses.filter((s) => s !== value) });

  return (
    <div className="hx-formblock">
      {other && <Alert tone="danger" title={t("tl.error.save")}>{other}</Alert>}
      {attempted && Object.keys(local).length > 0 && <Alert tone="danger">{t("tl.fixErrors")}</Alert>}
      {withPresets && (
        <FormField label={t("tl.form.preset")} hint={t("tl.form.presetHint")}>
          <Select aria-label={t("tl.form.preset")} value={preset} placeholder={t("tl.form.presetPlaceholder")}
            onChange={(v) => { setPreset(v); setForm((f) => applyPreset(f, v)); }}
            options={TRUSTED_LIST_PRESETS.map((p) => ({ value: p.id, label: t(`tl.preset.${p.id}`), description: p.url }))} />
        </FormField>
      )}
      <div className="hx-fieldgrid">
        <FormField label={t("tl.form.name")} required error={fe("name")} hint={t("tl.form.nameHint")}>
          <Input value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="eudi-pid-providers"
            autoComplete="off" spellCheck={false} />
        </FormField>
        <FormField label={t("tl.form.format")} required error={fe("format")}>
          <Select aria-label={t("tl.form.format")} value={form.format}
            onChange={(v) => set({ format: v as TrustedListForm["format"] })}
            options={[
              { value: "ETSI_119612_XML", label: t("tl.format.ETSI_119612_XML"), description: t("tl.format.xmlDesc") },
              { value: "ETSI_119602_JSON", label: t("tl.format.ETSI_119602_JSON"), description: t("tl.format.jsonDesc") },
            ]} />
        </FormField>
      </div>
      <FormField label={t("tl.form.url")} required error={fe("url")} hint={t("tl.form.urlHint")}>
        <Input value={form.url} onChange={(e) => set({ url: e.target.value })} placeholder="https://…" spellCheck={false}
          inputMode="url" />
      </FormField>
      <FormField label={t("tl.form.signers")} required error={fe("signerCertificates")} hint={t("tl.form.signersHint")}>
        <Textarea className="hx-mono" rows={5} value={form.signerCertificates} spellCheck={false}
          onChange={(e) => set({ signerCertificates: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----…" />
      </FormField>
      {signers && signers.signers.length > 0 && form.signerCertificates === signers.signerCertificates && (
        <ul className="hx-certlist" aria-label={t("tl.form.signersPreview")}>
          {signers.signers.map((c, i) => (
            <li key={`${c.serialNumber}-${i}`} className="hx-certlist__item">
              <div className="hx-certlist__head">
                <strong>{commonName(c.subject)}</strong>
                {expiryState(c.notAfter) === "expired"
                  ? <Badge tone="warning">{t("tl.signerExpired")}</Badge>
                  : <Badge tone="success">{t("wallet.key.valid")}</Badge>}
              </div>
              <div className="hx-certlist__meta">
                <span>{t("wallet.key.issuer")}: {commonName(c.issuer)}</span>
                <span>{t("wallet.key.validUntil")}: {absoluteTime(c.notAfter, locale)}</span>
                <span>{c.keyAlgorithm}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
      <FormField label={t("tl.form.types")} required error={fe("serviceTypes")} hint={t("tl.form.typesHint")}>
        <Textarea className="hx-mono" rows={2} value={form.serviceTypes} spellCheck={false}
          onChange={(e) => set({ serviceTypes: e.target.value })} placeholder="http://uri.etsi.org/Svc/Svctype/Provider/PID" />
      </FormField>
      {form.format === "ETSI_119612_XML" && (
        <>
          <FormField label={t("tl.form.statuses")} required error={fe("acceptedStatuses")} hint={t("tl.form.statusesHint")} group>
            <div className="hx-optiongrid">
              {STATUS_OPTIONS.map((s) => (
                <Checkbox key={s.value} checked={form.acceptedStatuses.includes(s.value)} onChange={(on) => toggleStatus(s.value, on)}
                  label={<span className="hx-optlabel"><span>{t(`tl.statusOpt.${s.key}`)}</span><span className="hx-optlabel__sub hx-mono">{`…/${s.value.slice(s.value.lastIndexOf("/") + 1)}`}</span></span>} />
              ))}
            </div>
          </FormField>
          <FormField label={t("tl.form.territories")} error={fe("territories")} hint={t("tl.form.territoriesHint")}>
            <Input value={form.territories} onChange={(e) => set({ territories: e.target.value })} placeholder="NL DE AT"
              spellCheck={false} autoComplete="off" />
          </FormField>
        </>
      )}
      <div className="hx-fieldgrid">
        <FormField label={t("tl.form.grace")} required error={fe("graceHours")} hint={t("tl.form.graceHint", { max: GRACE_RANGE.max })}>
          <Input inputMode="numeric" value={form.graceHours} onChange={(e) => set({ graceHours: e.target.value })} placeholder="24" />
        </FormField>
        <FormField label={t("tl.form.enabled")} hint={t("tl.form.enabledHint")}>
          <Switch checked={form.enabled} onChange={(on) => set({ enabled: on })} label={t("tl.form.enabledLabel")} />
        </FormField>
      </div>
      <div className="hx-formactions hx-formactions--end">
        {onCancel && <Button variant="ghost" onClick={onCancel} disabled={busy}>{t("common.cancel")}</Button>}
        <Button variant="primary" onClick={submit} disabled={busy}>{busy ? t("tl.form.saving") : submitLabel}</Button>
      </div>
    </div>
  );
}
