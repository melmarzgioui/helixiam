import type { Meta, StoryObj } from "@storybook/react";
import { Table, Column } from "./Table";
import { Badge } from "./Badge";

interface Conn {
  id: string;
  name: string;
  protocol: string;
  status: "enabled" | "draft" | "error";
}

const rows: Conn[] = [
  { id: "1", name: "DigiD (CombiConnect)", protocol: "SAML2", status: "enabled" },
  { id: "2", name: "eHerkenning", protocol: "SAML2", status: "enabled" },
  { id: "3", name: "eIDAS (EU)", protocol: "SAML2", status: "draft" },
  { id: "4", name: "Google Workspace", protocol: "OIDC", status: "enabled" },
  { id: "5", name: "Partner IdP", protocol: "SAML2", status: "error" },
];

const tone = { enabled: "success", draft: "neutral", error: "danger" } as const;

const columns: Column<Conn>[] = [
  { key: "name", header: "Connection", render: (r) => <strong style={{ fontWeight: 600 }}>{r.name}</strong> },
  { key: "protocol", header: "Protocol" },
  { key: "status", header: "Status", render: (r) => <Badge tone={tone[r.status]}>{r.status}</Badge> },
];

const meta: Meta = { title: "Components/Table" };
export default meta;
type Story = StoryObj;

export const Connections: Story = {
  render: () => (
    <div style={{ maxWidth: 680 }}>
      <Table columns={columns} rows={rows} rowKey={(r) => r.id} onRowClick={() => {}} />
    </div>
  ),
};
