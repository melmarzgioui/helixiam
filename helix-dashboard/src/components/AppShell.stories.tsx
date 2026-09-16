/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { AppShell } from "./AppShell";
import { Table, Column } from "./Table";
import { Badge } from "./Badge";
import { Button } from "./Button";

const meta: Meta<typeof AppShell> = {
  title: "Layout/AppShell",
  component: AppShell,
  parameters: { layout: "fullscreen" },
};
export default meta;
type Story = StoryObj<typeof AppShell>;

const icon = (d: string) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d={d} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const sections = [
  {
    items: [
      { id: "overview", label: "Overview", icon: icon("M4 13h7V4H4zM13 20h7v-9h-7zM13 4v5h7V4zM4 20h7v-5H4z") },
      { id: "providers", label: "Identity providers", icon: icon("M12 3l8 4v5c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V7z"), badge: <Badge tone="success">5</Badge> },
      { id: "clients", label: "Clients", icon: icon("M3 7h18M3 12h18M3 17h18") },
    ],
  },
  {
    title: "Realm",
    items: [
      { id: "users", label: "Users", icon: icon("M16 19a4 4 0 00-8 0M12 11a3 3 0 100-6 3 3 0 000 6") },
      { id: "sessions", label: "Sessions", icon: icon("M12 7v5l3 2M21 12a9 9 0 11-18 0 9 9 0 0118 0z") },
      { id: "flows", label: "Authentication flows", icon: icon("M6 3v6a3 3 0 003 3h6a3 3 0 013 3v3M6 21V9") },
    ],
  },
];

const columns: Column<{ id: string; name: string; protocol: string; status: "enabled" | "draft" | "error" }>[] = [
  { key: "name", header: "Connection", render: (r) => <strong style={{ fontWeight: 600 }}>{r.name}</strong> },
  { key: "protocol", header: "Protocol" },
  { key: "status", header: "Status", render: (r) => <Badge tone={({ enabled: "success", draft: "neutral", error: "danger" } as const)[r.status]}>{r.status}</Badge> },
];

const rows = [
  { id: "1", name: "DigiD (CombiConnect)", protocol: "SAML2", status: "enabled" as const },
  { id: "2", name: "eHerkenning", protocol: "SAML2", status: "enabled" as const },
  { id: "3", name: "eIDAS (EU)", protocol: "SAML2", status: "draft" as const },
  { id: "4", name: "Google Workspace", protocol: "OIDC", status: "enabled" as const },
];

export const Console: Story = {
  render: () => {
    const [active, setActive] = React.useState("providers");
    const [realm, setRealm] = React.useState("gov");
    return (
      <AppShell
        sections={sections}
        activeId={active}
        onNavigate={setActive}
        realms={[
          { value: "gov", label: "gov-nl" },
          { value: "internal", label: "internal" },
          { value: "partners", label: "partners" },
        ]}
        activeRealm={realm}
        onRealmChange={setRealm}
        user={{ name: "Mo Marz", email: "admin@kubedna.io" }}
        title="Identity providers"
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.2rem" }}>
          <p style={{ margin: 0, color: "var(--fg-muted)" }}>Connections users can sign in through, for the <strong>gov-nl</strong> realm.</p>
          <Button variant="primary">Add identity provider</Button>
        </div>
        <Table columns={columns} rows={rows} rowKey={(r) => r.id} onRowClick={() => {}} />
      </AppShell>
    );
  },
};
