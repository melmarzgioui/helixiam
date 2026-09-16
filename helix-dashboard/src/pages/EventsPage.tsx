/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { Toast, ToastTone } from "../components/Toast";
import { FormField, Input, Select } from "../components/FormField";
import { AuditApi, AuditConfig, AuditRecord } from "../api/audit";
import { useT } from "../i18n/LocaleContext";

export interface EventsPageProps {
  api: AuditApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/**
 * E8.5 (Events): read-only view of the server's audit / SIEM delivery configuration. Audit events are
 * security records (logins, admin changes) consumed by a SIEM/SOC — not browsed here. Delivery is
 * configured in the server's config file / environment (12-factor; secrets never editable from the UI),
 * and surfaced here read-only so operators can confirm where audit data is going.
 */
export function EventsPage({ api, realmId }: EventsPageProps) {
  const { t } = useT();
  const [cfg, setCfg] = React.useState<AuditConfig | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);
  const [rows, setRows] = React.useState<AuditRecord[] | null>(null);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(0);
  const [fType, setFType] = React.useState("");
  const [fActor, setFActor] = React.useState("");
  const [fOutcome, setFOutcome] = React.useState("");
  const [fCategory, setFCategory] = React.useState("");
  const SIZE = 50;

  const OUTCOMES = React.useMemo(() => [
    { value: "", label: t("events.outcome.any") },
    { value: "SUCCESS", label: t("events.outcome.success") },
    { value: "FAILURE", label: t("events.outcome.failure") },
  ], [t]);

  const CATEGORIES = React.useMemo(() => [
    { value: "", label: t("events.category.all") },
    { value: "AUTHN", label: t("events.category.authn") },
    { value: "ADMIN", label: t("events.category.admin") },
  ], [t]);

  const loadEvents = React.useCallback((p: number) => {
    setRows(null);
    api.search(realmId, { type: fType, actor: fActor, outcome: fOutcome, category: fCategory, page: p, size: SIZE })
      .then((res) => { setRows(res.items); setTotal(res.total); setPage(res.page); })
      .catch((e) => { setRows([]); setNote({ tone: "error", title: t("events.error.load"), message: String(e.message ?? e) }); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, realmId, fType, fActor, fOutcome, fCategory, t]);

  const reload = React.useCallback(() => {
    setCfg(null);
    api.getConfig().then(setCfg).catch((e) => setNote({ tone: "error", title: t("events.error.loadConfig"), message: String(e.message ?? e) }));
    loadEvents(0);
  }, [api, loadEvents, t]);

  React.useEffect(reload, [reload]);

  const fmtTs = (ts: string | null) => (ts ? ts.replace("T", " ").replace(/\.\d+Z?$/, "").replace("Z", "") : "—");

  return (
    <Page>
      <PageHeader
        title={t("events.title")}
        description={<>{t("events.description.pre")}<strong>{realmId}</strong>{t("events.description.post")}</>}
        actions={<Button variant="ghost" onClick={reload} disabled={cfg === null}>{t("events.action.refresh")}</Button>}
      />

      <PageBody>
        <Section title={t("common.search")} description={t("events.search.description")} layout="cols">
          <FormField label={t("events.field.eventType")}>
            <Input value={fType} onChange={(e) => setFType(e.target.value)} placeholder="LOGIN_SUCCESS" />
          </FormField>
          <FormField label={t("events.field.actor")}>
            <Input value={fActor} onChange={(e) => setFActor(e.target.value)} placeholder="username" />
          </FormField>
          <FormField label={t("events.field.category")}>
            <Select aria-label={t("events.field.category")} value={fCategory} onChange={setFCategory} options={CATEGORIES} />
          </FormField>
          <FormField label={t("events.field.outcome")}>
            <Select aria-label={t("events.field.outcome")} value={fOutcome} onChange={setFOutcome} options={OUTCOMES} />
          </FormField>
          <div className="hx-full hx-formactions hx-formactions--end">
            <Button variant="primary" onClick={() => loadEvents(0)}>{t("common.search")}</Button>
          </div>
        </Section>

        {rows === null ? (
          <div className="hx-loadwrap"><Spinner size={26} label={t("events.loading")} /></div>
        ) : (
          <>
            <div className="hx-card">
              <div className="hx-tablescroll">
                <table className="hx-table">
                  <thead><tr><th>{t("events.col.time")}</th><th>{t("events.col.type")}</th><th>{t("events.col.category")}</th><th>{t("events.col.actor")}</th><th>{t("events.col.sourceIp")}</th><th>{t("events.col.outcome")}</th></tr></thead>
                  <tbody>
                    {rows.length === 0 ? (
                      <tr><td colSpan={6} className="hx-cell-center hx-faint">{t("events.empty.msg")}</td></tr>
                    ) : rows.map((r, i) => (
                      <tr key={i}>
                        <td className="hx-mono hx-muted hx-nowrap">{fmtTs(r.ts)}</td>
                        <td className="hx-cell-strong">{r.type}</td>
                        <td>{r.category && <Badge tone="neutral">{r.category}</Badge>}</td>
                        <td>{r.actor ?? "—"}</td>
                        <td className="hx-mono hx-muted">{r.sourceIp ?? "—"}</td>
                        <td><Badge tone={r.outcome === "SUCCESS" ? "success" : r.outcome === "FAILURE" ? "danger" : "neutral"}>{r.outcome ?? "—"}</Badge></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="hx-formactions">
              <span className="hx-faint">
                {total === 1
                  ? t("events.pagination.one", { page: String(page + 1) })
                  : t("events.pagination.many", { total: String(total), page: String(page + 1) })}
              </span>
              <span className="hx-badges">
                <Button variant="ghost" onClick={() => loadEvents(page - 1)} disabled={page === 0}>{t("events.action.prev")}</Button>
                <Button variant="ghost" onClick={() => loadEvents(page + 1)} disabled={(page + 1) * SIZE >= total}>{t("events.action.next")}</Button>
              </span>
            </div>
          </>
        )}

        {cfg === null ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("events.loading.config")} /></div>
        ) : (
          <div className="hx-detailgrid">
            <Section title={t("events.status.title")} description={t("events.status.description")}>
              <Row label={t("events.status.emission.label")}>
                {cfg.enabled ? <Badge tone="success">{t("events.status.emission.enabled")}</Badge> : <Badge tone="warning">{t("events.status.emission.disabled")}</Badge>}
              </Row>
              <Row label={t("events.status.categories.label")}>
                <span className="hx-badges">
                  {cfg.categories.length ? cfg.categories.map((c) => <Badge key={c} tone="accent">{c}</Badge>) : <span className="hx-faint">{t("events.status.categories.none")}</span>}
                </span>
              </Row>
            </Section>

            <Section title={t("events.delivery.title")} description={t("events.delivery.description")}>
              <Row label={t("events.delivery.stdout.label")}>
                <Badge tone="success">{t("events.delivery.stdout.value")}</Badge>
              </Row>
              <Row label={t("events.delivery.http.label")}>
                {cfg.httpConfigured ? <Badge tone="success">{t("events.delivery.http.configured")}</Badge> : <Badge tone="neutral">{t("events.delivery.http.notConfigured")}</Badge>}
              </Row>
              {cfg.httpConfigured && (
                <>
                  <Row label={t("events.delivery.endpoint.label")}>
                    <code className="hx-mono">{cfg.httpUrl}</code>
                  </Row>
                  <Row label={t("events.delivery.auth.label")}>
                    {cfg.authConfigured ? <Badge tone="neutral">{t("events.delivery.auth.configured")}</Badge> : <Badge tone="warning">{t("events.delivery.auth.notSet")}</Badge>}
                  </Row>
                  <Row label={t("events.delivery.timeout.label")}>
                    <span className="hx-muted">{cfg.timeoutMs} ms</span>
                  </Row>
                </>
              )}
            </Section>

            <Section title={t("events.managed.title")}>
              <p className="hx-help">
                {t("events.managed.body.pre")}<code className="hx-mono">helix.audit.*</code>{t("events.managed.body.post")}
              </p>
            </Section>
          </div>
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

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="hx-togglerow">
      <span className="hx-togglerow__label">{label}</span>
      <span>{children}</span>
    </div>
  );
}
