import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { Badge, BadgeTone } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Alert } from "../components/Alert";
import { FormField, Input } from "../components/FormField";
import { CopyButton } from "../components/CopyButton";
import { CopyRow } from "../components/CopyRow";
import { Agent, agentStats, AgentStats } from "../api/agents";
import { fetchOidcEndpoints, OidcEndpoints } from "../api/endpoints";
import {
  mcpAgents,
  mcpTokens,
  registrationEndpoint,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
  wwwAuthenticateChallenge,
  validateResourceUrl,
} from "../api/mcp";
import { useT } from "../i18n/LocaleContext";

/** Public docs page for the full MCP authorization walkthrough. */
const DOCS_URL = "https://helixiam.com/docs/integration/mcp";

export interface McpPageProps {
  /** Lists the realm's agents (NHIs) so we can surface the MCP-capable ones. */
  agentsApi: { list(realmId: string): Promise<Agent[]> };
  realmId: string;
  /** Auth-server base URL (for the realm's discovery/endpoint lookup); defaults to same-origin. */
  apiBase?: string;
  /** Navigate to the Agents screen (management lives there — this page is read-only + generators). */
  onManageAgents?: () => void;
}

const STATUS_TONE: Record<string, BadgeTone> = {
  ACTIVE: "success", SUSPENDED: "warning", EXPIRED: "danger", REVOKED: "danger",
};

/** One governance overview tile — a big count over a label. */
function StatCard({ label, value, tone }: { label: string; value: number; tone?: "warn" }) {
  return (
    <Card>
      <div className="hx-stat">
        <div className={tone === "warn" ? "hx-stat__value hx-stat__value--warn" : "hx-stat__value"}>{value}</div>
        <div className="hx-stat__label">{label}</div>
      </div>
    </Card>
  );
}

/** A titled, copyable code output (JSON / header / command). */
function CodeOut({ title, value }: { title: string; value: string }) {
  return (
    <div className="hx-codeout">
      <div className="hx-codeout__head">
        <span className="hx-codeout__title">{title}</span>
        <CopyButton value={value} label={`Copy ${title}`} />
      </div>
      <pre className="hx-codeblock">{value}</pre>
    </div>
  );
}

export function McpPage({ agentsApi, realmId, apiBase = "", onManageAgents }: McpPageProps) {
  const { t } = useT();
  const [agents, setAgents] = React.useState<Agent[] | null>(null);
  const [endpoints, setEndpoints] = React.useState<OidcEndpoints | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [resource, setResource] = React.useState("");
  const [touched, setTouched] = React.useState(false);
  const [scopesText, setScopesText] = React.useState("openid mcp:tools");

  React.useEffect(() => {
    let live = true;
    setAgents(null);
    setEndpoints(null);
    setError(null);
    agentsApi.list(realmId).then((a) => live && setAgents(a)).catch((e) => live && setError(String(e.message ?? e)));
    fetchOidcEndpoints(realmId, apiBase).then((e) => live && setEndpoints(e)).catch(() => live && setEndpoints(null));
    return () => { live = false; };
  }, [agentsApi, apiBase, realmId]);

  const callers = agents ? mcpAgents(agents) : [];
  const stats: AgentStats | null = agents ? agentStats(callers, Date.now()) : null;
  const issuer = endpoints?.issuer ?? "";

  const resourceErrors = validateResourceUrl(resource);
  const generated = touched && resourceErrors.length === 0 && issuer
    ? {
        metadata: JSON.stringify(protectedResourceMetadata(resource, issuer, scopesText.split(/[,\s]+/).filter(Boolean)), null, 2),
        metadataUrl: protectedResourceMetadataUrl(resource),
        challenge: wwwAuthenticateChallenge(resource),
      }
    : null;

  const dcrCommand = issuer
    ? [
        `curl -X POST ${registrationEndpoint(issuer)} \\`,
        `  -H 'Content-Type: application/json' \\`,
        `  -d '{"client_name":"my-mcp-agent","grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_basic"}'`,
      ].join("\n")
    : "";

  return (
    <Page>
      <PageHeader
        title={t("mcp.title")}
        description={t("mcp.desc")}
        actions={<a className="hx-btn hx-btn--ghost" href={DOCS_URL} target="_blank" rel="noreferrer">{t("mcp.docs")}</a>}
      />
      <PageBody>
        {error && <Alert tone="danger" title={t("mcp.error.title")}>{error}</Alert>}

        {stats && (
          <div className="hx-agentstats">
            <StatCard label={t("mcp.stat.callers")} value={stats.total} />
            <StatCard label={t("mcp.stat.active")} value={stats.active} />
            <StatCard label={t("mcp.stat.expiringSoon")} value={stats.expiringSoon} tone={stats.expiringSoon ? "warn" : undefined} />
          </div>
        )}

        <Section title={t("mcp.how.title")} description={t("mcp.how.desc")}>
          <ol className="hx-steps">
            <li>{t("mcp.how.step1")}</li>
            <li>{t("mcp.how.step2")}</li>
            <li>{t("mcp.how.step3")}</li>
            <li>{t("mcp.how.step4")}</li>
            <li>{t("mcp.how.step5")}</li>
          </ol>
          <p className="hx-help">
            {t("mcp.how.audnote")} <a className="hx-link" href={DOCS_URL} target="_blank" rel="noreferrer">{t("mcp.how.readmore")}</a>
          </p>
        </Section>

        <Section title={t("mcp.endpoints.title")} description={t("mcp.endpoints.desc")}>
          {endpoints === null ? (
            <div className="hx-loadwrap"><Spinner size={24} label={t("mcp.endpoints.loading")} /></div>
          ) : (
            <>
              <CopyRow label={t("mcp.endpoint.issuer")} value={endpoints.issuer} />
              <CopyRow label={t("mcp.endpoint.discovery")} value={endpoints.discovery} />
              <CopyRow label={t("mcp.endpoint.token")} value={endpoints.token} />
              <CopyRow label={t("mcp.endpoint.registration")} value={registrationEndpoint(endpoints.issuer)} />
            </>
          )}
        </Section>

        <Section
          title={t("mcp.agents.title")}
          description={t("mcp.agents.desc")}
          actions={onManageAgents && <Button variant="ghost" onClick={onManageAgents}>{t("mcp.agents.manage")}</Button>}
        >
          {agents === null ? (
            <div className="hx-loadwrap"><Spinner size={24} label={t("mcp.agents.loading")} /></div>
          ) : callers.length === 0 ? (
            <EmptyState title={t("mcp.agents.empty.title")} message={t("mcp.agents.empty.msg")} />
          ) : (
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr>
                    <th>{t("mcp.agents.col.agent")}</th>
                    <th>{t("mcp.agents.col.owner")}</th>
                    <th>{t("mcp.agents.col.status")}</th>
                    <th>{t("mcp.agents.col.scopes")}</th>
                  </tr>
                </thead>
                <tbody>
                  {callers.map((a) => (
                    <tr key={a.id}>
                      <td>{a.displayName?.trim() || a.name}</td>
                      <td>{a.owner?.trim() || <span className="hx-faint">—</span>}</td>
                      <td><Badge tone={STATUS_TONE[a.status] ?? "neutral"}>{a.status}</Badge></td>
                      <td>
                        <div className="hx-badges">
                          {mcpTokens(a).map((tok) => <Badge key={tok} tone="accent">{tok}</Badge>)}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        <Section title={t("mcp.protect.title")} description={t("mcp.protect.desc")}>
          <FormField
            label={t("mcp.protect.resource.label")}
            hint={t("mcp.protect.resource.hint")}
            required
            error={touched && resourceErrors.includes("resource") ? t("mcp.protect.resource.error") : undefined}
          >
            <Input
              value={resource}
              placeholder="https://mcp.example.com"
              onChange={(e) => { setResource(e.target.value); setTouched(true); }}
              onBlur={() => setTouched(true)}
            />
          </FormField>
          <FormField label={t("mcp.protect.scopes.label")} hint={t("mcp.protect.scopes.hint")}>
            <Input value={scopesText} onChange={(e) => setScopesText(e.target.value)} placeholder="openid mcp:tools" />
          </FormField>

          {!issuer ? (
            <Alert tone="info" title={t("mcp.protect.noissuer.title")}>{t("mcp.protect.noissuer.msg")}</Alert>
          ) : !generated ? (
            <p className="hx-help">{t("mcp.protect.prompt")}</p>
          ) : (
            <PageBody>
              <CodeOut title={`GET ${protectedResourceMetadataUrl(resource)}`} value={generated.metadata} />
              <CodeOut title={t("mcp.protect.challenge")} value={generated.challenge} />
              <CodeOut title={t("mcp.protect.dcr")} value={dcrCommand} />
            </PageBody>
          )}
        </Section>
      </PageBody>
    </Page>
  );
}
