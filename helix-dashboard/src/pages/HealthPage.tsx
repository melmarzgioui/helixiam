import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Alert } from "../components/Alert";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { Toast, ToastTone } from "../components/Toast";
import { HealthApi, HealthSnapshot, MetricsSummary } from "../api/health";
import { useT } from "../i18n/LocaleContext";

export interface HealthPageProps {
  api: HealthApi;
  realmId: string;
}

const COUNT_KEYS = ["applications", "oidcClients", "samlRelyingParties", "identityProviders"] as const;

/** E8.6: live platform health for the realm — component status (edge / queue / domain / DB) + key counts. */
export function HealthPage({ api, realmId }: HealthPageProps) {
  const { t } = useT();
  const [snap, setSnap] = React.useState<HealthSnapshot | null>(null);
  const [metrics, setMetrics] = React.useState<MetricsSummary | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [note, setNote] = React.useState<{ tone: ToastTone; title: string; message?: string } | null>(null);

  const reload = React.useCallback(() => {
    setLoading(true);
    setError(null);
    api.get(realmId)
      .then((s) => setSnap(s))
      .catch((e) => setError(String(e.message ?? e)))
      .finally(() => setLoading(false));
    // Metrics are best-effort (additive) — never block or error the page on them.
    api.metrics(realmId).then(setMetrics).catch(() => setMetrics(null));
  }, [api, realmId]);
  React.useEffect(reload, [reload]);

  const overallUp = snap?.overall === "healthy";

  return (
    <Page>
      <PageHeader
        title={t("health.title")}
        description={t("health.description", { realmId })}
        actions={<Button variant="ghost" onClick={reload} disabled={loading}>{loading ? t("health.action.checking") : t("health.action.refresh")}</Button>}
      />

      <PageBody>
        {snap === null && error ? (
          <Alert tone="danger" title={t("health.error.load")}>{error}</Alert>
        ) : snap === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("health.checking")} />
          </div>
        ) : (
          <>
            {/* overall banner */}
            <Alert tone={overallUp ? "success" : "danger"} title={overallUp ? t("health.alert.operational") : t("health.alert.degraded")}>
              {t("health.checked", { ago: timeAgo(snap.checkedAt) })}
            </Alert>

            {/* component grid */}
            <Section title={t("health.section.components")} layout="cols">
              {snap.components.map((c) => (
                <Card key={c.name}>
                  <StatBlock>
                    <div className="hx-namecell">
                      <Badge tone={c.status === "up" ? "success" : "danger"}>{c.status === "up" ? t("health.component.up") : t("health.status.down")}</Badge>
                      <strong>{c.name}</strong>
                    </div>
                    <div className="hx-help">{c.detail}</div>
                  </StatBlock>
                </Card>
              ))}
            </Section>

            {/* counts */}
            <Section title={t("health.section.inventory")} layout="cols">
              {COUNT_KEYS.map((key) => (
                <Stat
                  key={key}
                  label={t(`health.count.${key}`)}
                  value={snap.counts[key] != null ? snap.counts[key] : <span className="hx-faint">—</span>}
                />
              ))}
            </Section>

            {/* IAM metrics (best-effort; from /admin/metrics/summary — raw series at /actuator/prometheus) */}
            {metrics && !metrics.error && (
              <Section
                title={t("health.section.metrics")}
                description={<>{t("health.metrics.description.prefix")} <code>/actuator/prometheus</code>.</>}
                layout="cols"
              >
                <Stat label={t("health.metric.loginSuccessRate")} value={metrics.loginSuccessRate != null ? `${Math.round(metrics.loginSuccessRate * 100)}%` : "—"} />
                <Stat label={t("health.metric.loginSuccess")} value={String(metrics.loginSuccess)} />
                <Stat label={t("health.metric.loginFailure")} value={String(metrics.loginFailure)} tone={metrics.loginFailure > 0 ? "warn" : undefined} />
                <Stat label={t("health.metric.mfaFailure")} value={String(metrics.mfaFailure)} tone={metrics.mfaFailure > 0 ? "warn" : undefined} />
                <Stat label={t("health.metric.tokensIssued")} value={String(metrics.tokensIssued)} />
                <Stat label={t("health.metric.adminWrites")} value={String(metrics.adminWrites)} />
              </Section>
            )}
          </>
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

/** Small vertical stack for a stat/status cell (value + label). */
function StatBlock({ children }: { children: React.ReactNode }) {
  return (
    <div className="hx-stat">
      {children}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: "warn" }) {
  return (
    <Card>
      <StatBlock>
        <div className={tone === "warn" ? "hx-stat__value hx-stat__value--warn" : "hx-stat__value"}>
          {value}
        </div>
        <div className="hx-stat__label">{label}</div>
      </StatBlock>
    </Card>
  );
}

function timeAgo(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "just now";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  return `${Math.round(secs / 60)}m ago`;
}
