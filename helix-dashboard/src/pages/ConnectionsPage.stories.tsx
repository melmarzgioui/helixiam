import type { Meta, StoryObj } from "@storybook/react";
import { ConnectionsPage } from "./ConnectionsPage";
import { createMemoryClient } from "../api/client";

const meta: Meta<typeof ConnectionsPage> = {
  title: "Pages/ConnectionsPage",
  component: ConnectionsPage,
  parameters: { layout: "padded" },
};
export default meta;
type Story = StoryObj<typeof ConnectionsPage>;

const seeded = createMemoryClient([
  { realmId: "gov", alias: "digid", protocol: "digid", displayName: "DigiD (CombiConnect)", enabled: true, config: {} },
  { realmId: "gov", alias: "eherkenning", protocol: "eherkenning", displayName: "eHerkenning", enabled: true, config: {} },
  { realmId: "gov", alias: "corp", protocol: "oidc", displayName: "Corp SSO", enabled: false, config: {} },
]);

export const WithConnections: Story = {
  render: () => <ConnectionsPage api={seeded} realmId="gov" />,
};

export const Empty: Story = {
  render: () => <ConnectionsPage api={createMemoryClient()} realmId="gov" />,
};
