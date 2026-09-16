/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { AppShell, NavSection } from "./components/AppShell";
import { fetchProfile, logout, type AdminIdentity } from "./api/session";
import { Badge } from "./components/Badge";
import { ConnectionsPage } from "./pages/ConnectionsPage";
import { ConnectionDetailPage } from "./pages/ConnectionDetailPage";
import { UserFederationPage } from "./pages/UserFederationPage";
import { EidAssurancePage } from "./pages/EidAssurancePage";
import { HealthPage } from "./pages/HealthPage";
import { createHealthHttpClient } from "./api/health";
import { UserDetailPage } from "./pages/UserDetailPage";
import { createCredentialHttpClient } from "./api/credentials";
import { UsersPage } from "./pages/UsersPage";
import { RolesPage } from "./pages/RolesPage";
import { ApplicationsPage } from "./pages/ApplicationsPage";
import { ApplicationDetailPage } from "./pages/ApplicationDetailPage";
import { createSamlClientHttpClient } from "./api/samlClients";
import { createApplicationHttpClient } from "./api/applications";
import { ClientScopesPage } from "./pages/ClientScopesPage";
import { ScopeDetailPage } from "./pages/ScopeDetailPage";
import { ClaimsPage } from "./pages/ClaimsPage";
import { RealmSettingsPage } from "./pages/RealmSettingsPage";
import { SessionsPage } from "./pages/SessionsPage";
import { AuthFlowPage } from "./pages/AuthFlowPage";
import { GroupsPage } from "./pages/GroupsPage";
import { EventsPage } from "./pages/EventsPage";
import { ProvisioningPage } from "./pages/ProvisioningPage";
import { createProvisioningHttpClient } from "./api/provisioning";
import { OrganizationsPage } from "./pages/OrganizationsPage";
import { createOrganizationHttpClient } from "./api/organizations";
import { AdminRolesPage } from "./pages/AdminRolesPage";
import { createAdminRoleHttpClient } from "./api/adminRoles";
import { ImportExportPage } from "./pages/ImportExportPage";
import { createRealmIoHttpClient } from "./api/realmIo";
import { GdprPrivacyPage } from "./pages/GdprPrivacyPage";
import { createGdprHttpClient } from "./api/gdpr";
import { RealmKeysPage } from "./pages/RealmKeysPage";
import { createRealmKeyHttpClient } from "./api/keys";
import { WebhooksPage } from "./pages/WebhooksPage";
import { createWebhookHttpClient } from "./api/webhooks";
import { WorkloadIdentityPage } from "./pages/WorkloadIdentityPage";
import { createWorkloadIdentityHttpClient } from "./api/workloadIdentity";
import { AgentsPage } from "./pages/AgentsPage";
import { createAgentsHttpClient } from "./api/agents";
import { McpPage } from "./pages/McpPage";
import { LocaleProvider, useT } from "./i18n/LocaleContext";
import { InProgressPage } from "./pages/InProgressPage";
import { createHttpClient } from "./api/client";
import { createUserHttpClient } from "./api/users";
import { createRoleHttpClient } from "./api/roles";
import { createClientHttpClient } from "./api/clients";
import { createRealmHttpClient } from "./api/realm";
import { createSessionHttpClient } from "./api/sessions";
import { NotificationsPage } from "./pages/NotificationsPage";
import { createMessagingHttpClient } from "./api/messaging";
import { createFlowHttpClient } from "./api/flows";
import { createGroupHttpClient } from "./api/groups";
import { createAuditHttpClient } from "./api/audit";
import { createClaimHttpClient, createScopeHttpClient } from "./api/scopes";
import { createMapperHttpClient } from "./api/mappers";
import { createClientRoleHttpClient } from "./api/clientRoles";
import { createAuthzHttpClient } from "./api/authz";
import { useTheme } from "./hooks/useTheme";

const icon = (d: string) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d={d} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const REALMS = [
  { value: "gov", label: "gov" },
  { value: "internal", label: "internal" },
  { value: "master", label: "master" },
];

/** API base URL — set VITE_API_BASE to the auth server (e.g. http://localhost:8083); defaults to same-origin. */
const api = createHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const userApi = createUserHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const roleApi = createRoleHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const clientApi = createClientHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const samlClientApi = createSamlClientHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const applicationApi = createApplicationHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const realmApi = createRealmHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const sessionApi = createSessionHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const messagingApi = createMessagingHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const flowApi = createFlowHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const groupApi = createGroupHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const auditApi = createAuditHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const claimApi = createClaimHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const scopeApi = createScopeHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const mapperApi = createMapperHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const clientRoleApi = createClientRoleHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const authzApi = createAuthzHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const healthApi = createHealthHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const credentialApi = createCredentialHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const provisioningApi = createProvisioningHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const organizationApi = createOrganizationHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const adminRoleApi = createAdminRoleHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const realmIoApi = createRealmIoHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const gdprApi = createGdprHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const realmKeyApi = createRealmKeyHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const webhookApi = createWebhookHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const workloadIdentityApi = createWorkloadIdentityHttpClient(import.meta.env?.VITE_API_BASE ?? "");
const agentsApi = createAgentsHttpClient(import.meta.env?.VITE_API_BASE ?? "");

const ICONS = {
  clients: "M4 7h16M4 12h16M4 17h10",
  apps: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
  scopes: "M12 3l8 4.5v9L12 21l-8-4.5v-9z",
  claims: "M11 4H6a2 2 0 00-2 2v5l9 9 7-7-9-9zM8.5 8.5h.01",
  roles: "M9 12l2 2 4-4M12 3l8 4v5c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V7z",
  users: "M16 19a4 4 0 00-8 0M12 11a3 3 0 100-6 3 3 0 000 6",
  groups: "M17 20v-1a4 4 0 00-4-4H7a4 4 0 00-4 4v1M9 11a3 3 0 100-6 3 3 0 000 6M19 11a3 3 0 10-2-5",
  orgs: "M4 21V6a1 1 0 011-1h7a1 1 0 011 1v15M13 21V10h6a1 1 0 011 1v10M7 9h3M7 13h3M7 17h3M16 14h1M16 18h1",
  sessions: "M12 7v5l3 2M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  events: "M4 5h16v14H4zM4 9h16M8 3v4M16 3v4",
  settings: "M4 7h16M4 12h16M4 17h16M14 5v4M8 10v4M17 15v4",
  realm: "M3 12l9-9 9 9M5 10v10h14V10",
  auth: "M12 15v2M8 11V8a4 4 0 018 0v3M6 11h12v9H6z",
  webhooks: "M14 4h6v6M20 4l-8 8M18 13v5a1 1 0 01-1 1H6a1 1 0 01-1-1V7a1 1 0 011-1h5",
  workloadIdentity: "M12 2l8 4.5v9L12 20l-8-4.5v-9L12 2zM12 2v18M4 6.5l8 4.5 8-4.5",
  notifications: "M6 9a6 6 0 1112 0c0 6 2 8 2 8H4s2-2 2-8M10 21a2 2 0 004 0",
  providers: "M15 4h3a2 2 0 012 2v12a2 2 0 01-2 2h-3M10 16l4-4-4-4M14 12H4",
  provisioning: "M4 9a8 8 0 0114-2.5L20 8M20 15a8 8 0 01-14 2.5L4 16M20 5v3h-3M4 19v-3h3",
  adminRoles: "M12 3l7 3v5c0 4.5-3 7-7 8.5-4-1.5-7-4-7-8.5V6zM12 11a1.6 1.6 0 100-3.2 1.6 1.6 0 000 3.2M9 15.5a3 3 0 016 0",
  importExport: "M8 21V9m0 0L5 12m3-3l3 3M16 3v12m0 0l3-3m-3 3l-3-3",
  privacy: "M12 3l7 3v5c0 4.5-3 7-7 8.5-4-1.5-7-4-7-8.5V6zM10 11.5v-1a2 2 0 014 0v1M9.5 11.5h5v3.5h-5z",
  federation: "M12 3v6m0 6v6M3 12h6m6 0h6M7 7l3 3m4 4l3 3M17 7l-3 3m-4 4l-3 3",
  device: "M9 3h6a2 2 0 012 2v14a2 2 0 01-2 2H9a2 2 0 01-2-2V5a2 2 0 012-2zM11 18h2",
  eid: "M3 7h18v10H3zM7 12h.01M11 11h6M11 14h4",
  health: "M3 12h4l2 6 4-14 2 8h6",
  keys: "M15 7a4 4 0 11-3.9 5H8v3H5v-3H3.1A4 4 0 1115 7zM7 11a1 1 0 100-2 1 1 0 000 2z",
  mcp: "M9 3v5M15 3v5M7 8h10v3a5 5 0 01-10 0V8zM12 16v5",
};

/** Section metadata for the not-yet-live screens (each ships backend + UI together). */
const PAGES: Record<string, React.ComponentProps<typeof InProgressPage> & { section: string }> = {
  clients: {
    section: "clients",
    title: "Clients",
    blurb: "OAuth 2.1 / OIDC applications and services that trust this realm to sign users in.",
    icon: icon(ICONS.clients),
    capabilities: [
      "Register confidential & public clients (PKCE, client_credentials, device, CIBA)",
      "Per-client redirect URIs, scopes, token lifetimes and FAPI policies",
      "Client roles + which identity providers each client may use",
      "Rotate client secrets and download client config",
    ],
    beyond: "clients can be pinned to specific identity providers and assurance levels, and inherit realm FAPI/DPoP policy by default.",
  },
  scopes: {
    section: "clients",
    title: "Client scopes",
    blurb: "Reusable sets of claims and role mappings that clients request at authorization time.",
    icon: icon(ICONS.scopes),
    capabilities: [
      "Default vs optional scopes with consent control",
      "Protocol mappers (claims) shared across clients",
      "Role-scope mappings",
    ],
    beyond: "scopes carry a data-minimisation tag so eID flows only release the BSN/KvK attributes a client is authorised for.",
  },
  roles: {
    section: "roles",
    title: "Realm & client roles",
    blurb: "The authorization model — realm-wide roles and per-client roles, composable into bundles.",
    icon: icon(ICONS.roles),
    capabilities: [
      "Create realm roles and client roles",
      "Composite roles (roles that grant other roles)",
      "Assign roles to users and groups",
      "See effective roles per user, resolved through groups + composites",
    ],
    beyond: "an effective-permissions explainer shows exactly why a user has a role (direct, via group, or via composite).",
  },
  groups: {
    section: "groups",
    title: "Groups",
    blurb: "Hierarchical groups that bundle role mappings and attributes for sets of users.",
    icon: icon(ICONS.groups),
    capabilities: [
      "Nested group tree with inherited role mappings",
      "Group attributes applied to member tokens",
      "Bulk membership management",
    ],
    beyond: "groups can be mapped from an external IdP claim so federated users land in the right group automatically.",
  },
  sessions: {
    section: "sessions",
    title: "Sessions",
    blurb: "Live user and client sessions across the realm — inspect and revoke in real time.",
    icon: icon(ICONS.sessions),
    capabilities: [
      "List active sessions per user / client with device + IP",
      "Revoke a single session or all of a user's sessions",
      "Back-channel logout to clients",
    ],
    beyond: "sessions show the assurance level and authenticators used (passkey, device push, eID) for each login.",
  },
  events: {
    section: "events",
    title: "Events",
    blurb: "Login and admin audit events — who did what, when, from where.",
    icon: icon(ICONS.events),
    capabilities: [
      "Login events (success/failure, MFA, IdP) with filtering",
      "Admin audit events for every config change",
      "Export and stream to SIEM",
    ],
    beyond: "events are tamper-evident and map directly to the compliance evidence export used by the autopilot.",
  },
  realm: {
    section: "realm",
    title: "Realm settings",
    blurb: "Login policy, tokens, keys, themes and security defaults for this realm.",
    icon: icon(ICONS.realm),
    capabilities: [
      "Login: self-registration, email verification, password policy",
      "Tokens: access/refresh TTLs, reuse, algorithms",
      "Keys: per-realm signing keys with zero-downtime rotation",
    ],
    beyond: "per-realm KMS/HSM-backed keys rotate live with an overlap window — no downtime, already wired in E1.4.",
  },
  auth: {
    section: "auth",
    title: "Authentication",
    blurb: "The flow engine — order authenticators and requirements for browser, device and step-up flows.",
    icon: icon(ICONS.auth),
    capabilities: [
      "Visual flow editor over the existing flow engine (E2)",
      "Bind flows to clients and actions",
      "Required actions and conditional step-up",
    ],
    beyond: "flows include first-class VeridPay-style device push, WYSIWYS transaction signing and eID step-up authenticators.",
  },
  federation: {
    section: "federation",
    title: "User federation",
    blurb: "Sync or delegate to external user stores — LDAP / Active Directory and custom providers.",
    icon: icon(ICONS.federation),
    capabilities: [
      "LDAP / AD federation with attribute & group mappers",
      "Import vs always-delegate sync modes",
      "Per-provider failover and caching",
    ],
    beyond: "shares the same SPI as identity brokering, so a directory and a social login coexist on one user.",
  },
  device: {
    section: "extras",
    title: "Device & passkeys",
    blurb: "Enrolled mobile devices, passkeys and recovery factors per user.",
    icon: icon(ICONS.device),
    capabilities: [
      "Enrolled device credentials with attestation",
      "Passkeys (FIDO2) and HOTP/recovery codes",
      "QR cross-device login and push approvals",
    ],
    beyond: "a full VeridPay-class device factor — number matching, WYSIWYS signing — built in, not a bolt-on plugin.",
  },
  eid: {
    section: "extras",
    title: "eID & assurance",
    blurb: "Dutch & EU electronic IDs and the level-of-assurance policy per client.",
    icon: icon(ICONS.eid),
    capabilities: [
      "DigiD, eHerkenning and eIDAS connectors out of the box",
      "Per-client minimum level of assurance",
      "Representation / authorisation (machtigingen) routing",
    ],
    beyond: "eIDAS/eHerkenning/DigiD ship as first-class presets — no custom extensions required.",
  },
  health: {
    section: "extras",
    title: "Health & observability",
    blurb: "Live health of the IAM platform — services, queues, keys and login success rates.",
    icon: icon(ICONS.health),
    capabilities: [
      "Service + dependency health (DB, Redis, AMQP)",
      "Login success/failure and latency trends",
      "Key rotation and certificate expiry warnings",
    ],
    beyond: "an operational dashboard built into the admin console (E8.6) — not a separate Grafana stack.",
  },
};

/** Parse a shareable URL (/realms/:realm/:section[/:detail]) into its parts, or null for the bare root. */
function parseRoute(): { realm: string; section: string; detail: string | null } | null {
  const m = window.location.pathname.match(/^\/realms\/([^/]+)\/([^/]+)(?:\/([^/]+))?\/?$/);
  return m ? { realm: decodeURIComponent(m[1]), section: m[2], detail: m[3] ? decodeURIComponent(m[3]) : null } : null;
}

const routePath = (realm: string, section: string, detail?: string | null) =>
  `/realms/${encodeURIComponent(realm)}/${section}${detail ? `/${encodeURIComponent(detail)}` : ""}`;

function AppInner() {
  const { t } = useT();
  const initialRoute = parseRoute();
  const [active, setActive] = React.useState(initialRoute?.section ?? "providers");
  const [realm, setRealm] = React.useState(initialRoute?.realm ?? "master");
  const [detail, setDetail] = React.useState<string | null>(initialRoute?.detail ?? null);
  const { theme, toggle } = useTheme();

  // The signed-in admin shown in the header — resolved from the session's account profile.
  const [me, setMe] = React.useState<AdminIdentity>({ name: "Admin" });
  React.useEffect(() => { void fetchProfile().then((p) => { if (p) setMe(p); }); }, []);

  // Shareable, deep-linkable URLs: reflect the realm + section (+ detail id) in the path; sync on back/forward.
  React.useEffect(() => {
    if (!parseRoute()) {
      window.history.replaceState(null, "", routePath(realm, active, detail));
    }
    const onPop = () => {
      const r = parseRoute();
      if (r) { setRealm(r.realm); setActive(r.section); setDetail(r.detail); }
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const navigate = React.useCallback((nextRealm: string, nextSection: string, nextDetail?: string | null) => {
    setRealm(nextRealm);
    setActive(nextSection);
    setDetail(nextDetail ?? null);
    const path = routePath(nextRealm, nextSection, nextDetail);
    if (window.location.pathname !== path) {
      window.history.pushState(null, "", path);
    }
  }, []);

  const goSection = React.useCallback((section: string) => navigate(realm, section), [navigate, realm]);
  const goRealm = React.useCallback((nextRealm: string) => navigate(nextRealm, active), [navigate, active]);
  const openDetail = React.useCallback((section: string, id: string) => navigate(realm, section, id), [navigate, realm]);

  // Nav mirrors the documentation site's subject structure exactly: Manage (Realms, Applications &
  // clients, Users & access, Sessions), Authentication, Federation & eIDs, Integration, Operations,
  // Compliance & security. Items are ordered within Manage by those sub-areas.
  const sections: NavSection[] = [
    {
      title: t("nav.section.manage"),
      items: [
        // Realms
        { id: "realm", label: t("nav.realm"), icon: icon(ICONS.settings) },
        { id: "keys", label: t("nav.keys"), icon: icon(ICONS.keys) },
        { id: "notifications", label: t("nav.notifications"), icon: icon(ICONS.notifications) },
        // Applications & clients
        { id: "applications", label: t("nav.applications"), icon: icon(ICONS.apps) },
        { id: "scopes", label: t("nav.scopes"), icon: icon(ICONS.scopes) },
        { id: "claims", label: t("nav.claims"), icon: icon(ICONS.claims) },
        // Users & access
        { id: "users", label: t("nav.users"), icon: icon(ICONS.users) },
        { id: "groups", label: t("nav.groups"), icon: icon(ICONS.groups) },
        { id: "organizations", label: t("nav.organizations"), icon: icon(ICONS.orgs) },
        { id: "roles", label: t("nav.roles"), icon: icon(ICONS.roles) },
        { id: "admin-roles", label: t("nav.adminRoles"), icon: icon(ICONS.adminRoles) },
        // Sessions
        { id: "sessions", label: t("nav.sessions"), icon: icon(ICONS.sessions) },
      ],
    },
    {
      title: t("nav.section.authentication"),
      items: [
        { id: "auth", label: t("nav.auth"), icon: icon(ICONS.auth) },
      ],
    },
    {
      title: t("nav.section.federation"),
      items: [
        { id: "providers", label: t("nav.providers"), icon: icon(ICONS.providers), badge: <Badge tone="accent">{t("common.live")}</Badge> },
        { id: "federation", label: t("nav.federation"), icon: icon(ICONS.federation) },
        { id: "eid", label: t("nav.eid"), icon: icon(ICONS.eid) },
      ],
    },
    {
      title: t("nav.section.integration"),
      items: [
        { id: "agents", label: t("nav.agents"), icon: icon(ICONS.workloadIdentity), badge: <Badge tone="accent">{t("app.badge.new")}</Badge> },
        { id: "mcp", label: t("nav.mcp"), icon: icon(ICONS.mcp), badge: <Badge tone="accent">{t("app.badge.new")}</Badge> },
        { id: "workload-identity", label: t("nav.workloadIdentity"), icon: icon(ICONS.workloadIdentity) },
        { id: "webhooks", label: t("nav.webhooks"), icon: icon(ICONS.webhooks) },
        { id: "provisioning", label: t("nav.provisioning"), icon: icon(ICONS.provisioning) },
        { id: "import-export", label: t("nav.importExport"), icon: icon(ICONS.importExport) },
      ],
    },
    {
      title: t("nav.section.operations"),
      items: [
        { id: "health", label: t("nav.health"), icon: icon(ICONS.health) },
      ],
    },
    {
      title: t("nav.section.compliance"),
      items: [
        { id: "events", label: t("nav.events"), icon: icon(ICONS.events) },
        { id: "gdpr", label: t("nav.gdpr"), icon: icon(ICONS.privacy) },
      ],
    },
  ];

  const TITLES: Record<string, string> = {
    providers: t("app.title.providers"),
    users: t("app.title.users"),
    roles: t("app.title.roles"),
    applications: t("app.title.applications"),
    scopes: t("app.title.scopes"),
    claims: t("app.title.claims"),
    realm: t("app.title.realm"),
    keys: t("app.title.keys"),
    webhooks: t("app.title.webhooks"),
    "workload-identity": t("app.title.workloadIdentity"),
    agents: t("app.title.agents"),
    mcp: t("app.title.mcp"),
    sessions: t("app.title.sessions"),
    auth: t("app.title.auth"),
    groups: t("app.title.groups"),
    events: t("app.title.events"),
    notifications: t("app.title.notifications"),
    provisioning: t("app.title.provisioning"),
    organizations: t("app.title.organizations"),
    "admin-roles": t("app.title.adminRoles"),
    "import-export": t("app.title.importExport"),
    gdpr: t("app.title.gdpr"),
  };
  const titleOf = TITLES[active] ?? PAGES[active]?.title ?? "Helix IAM";

  return (
    <AppShell
      sections={sections}
      activeId={active}
      onNavigate={goSection}
      realms={REALMS}
      activeRealm={realm}
      onRealmChange={goRealm}
      user={me}
      onLogout={logout}
      title={titleOf}
      theme={theme}
      onToggleTheme={toggle}
    >
      {active === "providers" ? (
        detail ? (
          <ConnectionDetailPage api={api} realmId={realm} alias={detail} onBack={() => goSection("providers")} onDeleted={() => goSection("providers")} />
        ) : (
          <ConnectionsPage api={api} realmId={realm} onOpen={(alias) => openDetail("providers", alias)} />
        )
      ) : active === "federation" ? (
        detail ? (
          <ConnectionDetailPage api={api} realmId={realm} alias={detail} onBack={() => goSection("federation")} onDeleted={() => goSection("federation")} />
        ) : (
          <UserFederationPage api={api} realmId={realm} onOpen={(alias) => openDetail("federation", alias)} />
        )
      ) : active === "eid" ? (
        <EidAssurancePage api={api} realmId={realm} />
      ) : active === "health" ? (
        <HealthPage api={healthApi} realmId={realm} />
      ) : active === "users" ? (
        detail ? (
          <UserDetailPage api={userApi} roleApi={roleApi} credentialApi={credentialApi} sessionApi={sessionApi} realmId={realm} userId={detail} onBack={() => goSection("users")} />
        ) : (
          <UsersPage api={userApi} roleApi={roleApi} realmId={realm} onOpen={(id) => openDetail("users", id)} />
        )
      ) : active === "roles" ? (
        <RolesPage api={roleApi} adminApi={adminRoleApi} realmId={realm} />
      ) : active === "applications" ? (
        detail ? (
          <ApplicationDetailPage api={applicationApi} clientApi={clientApi} samlClientApi={samlClientApi} claimApi={claimApi} flowApi={flowApi} scopeApi={scopeApi} mapperApi={mapperApi} clientRoleApi={clientRoleApi} roleApi={roleApi} authzApi={authzApi} workloadIdentityApi={workloadIdentityApi} agentsApi={agentsApi} idpApi={api} onManageMapping={(alias) => openDetail("providers", alias)} realmId={realm} name={detail} onBack={() => goSection("applications")} />
        ) : (
          <ApplicationsPage api={applicationApi} clientApi={clientApi} samlClientApi={samlClientApi} realmId={realm} onOpen={(name) => openDetail("applications", name)} />
        )
      ) : active === "scopes" ? (
        detail ? (
          <ScopeDetailPage api={scopeApi} claimApi={claimApi} realmId={realm} scopeId={detail} onBack={() => goSection("scopes")} />
        ) : (
          <ClientScopesPage api={scopeApi} realmId={realm} onOpen={(id) => openDetail("scopes", id)} />
        )
      ) : active === "claims" ? (
        <ClaimsPage api={claimApi} realmId={realm} />
      ) : active === "realm" ? (
        <RealmSettingsPage api={realmApi} realmId={realm} />
      ) : active === "keys" ? (
        <RealmKeysPage api={realmKeyApi} realmId={realm} />
      ) : active === "webhooks" ? (
        <WebhooksPage api={webhookApi} realmId={realm} />
      ) : active === "workload-identity" ? (
        <WorkloadIdentityPage api={workloadIdentityApi} realmId={realm} readOnly />
      ) : active === "agents" ? (
        <AgentsPage api={agentsApi} realmId={realm} userApi={userApi} clientApi={clientApi} roleApi={roleApi} clientRoleApi={clientRoleApi} />
      ) : active === "mcp" ? (
        <McpPage agentsApi={agentsApi} realmId={realm} apiBase={import.meta.env?.VITE_API_BASE ?? ""} onManageAgents={() => goSection("agents")} />
      ) : active === "sessions" ? (
        <SessionsPage api={sessionApi} realmId={realm} />
      ) : active === "auth" ? (
        <AuthFlowPage api={flowApi} realmId={realm} />
      ) : active === "notifications" ? (
        <NotificationsPage api={messagingApi} realmId={realm} />
      ) : active === "groups" ? (
        <GroupsPage api={groupApi} userApi={userApi} roleApi={roleApi} realmId={realm} />
      ) : active === "events" ? (
        <EventsPage api={auditApi} realmId={realm} />
      ) : active === "provisioning" ? (
        <ProvisioningPage api={provisioningApi} realmId={realm} />
      ) : active === "organizations" ? (
        <OrganizationsPage api={organizationApi} userApi={userApi} realmId={realm} />
      ) : active === "admin-roles" ? (
        <AdminRolesPage api={adminRoleApi} realmId={realm} />
      ) : active === "import-export" ? (
        <ImportExportPage api={realmIoApi} realmId={realm} />
      ) : active === "gdpr" ? (
        <GdprPrivacyPage api={gdprApi} userApi={userApi} realmId={realm} />
      ) : PAGES[active] ? (
        <InProgressPage {...PAGES[active]} />
      ) : (
        <InProgressPage title="Helix IAM" blurb={t("app.selectSection")} capabilities={[]} />
      )}
    </AppShell>
  );
}

/** Root: provides the locale context (en/nl) so the console chrome + language switcher localize. */
export function App() {
  return (
    <LocaleProvider>
      <AppInner />
    </LocaleProvider>
  );
}
