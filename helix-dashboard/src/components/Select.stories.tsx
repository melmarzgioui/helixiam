import type { Meta, StoryObj } from "@storybook/react";
import { Select } from "./Select";

const meta: Meta<typeof Select> = {
  title: "Components/Select",
  component: Select,
};
export default meta;

type Story = StoryObj<typeof Select>;

const protocols = [
  { value: "oidc", label: "OpenID Connect" },
  { value: "saml2", label: "SAML 2.0 (SP)" },
  { value: "ldap", label: "LDAP / Active Directory" },
  { value: "social", label: "Social (Google, GitHub, …)" },
];

export const Default: Story = {
  render: () => (
    <div style={{ maxWidth: 380 }}>
      <Select options={protocols} placeholder="Choose a protocol…" aria-label="Protocol" />
    </div>
  ),
};

export const Preselected: Story = {
  render: () => (
    <div style={{ maxWidth: 380 }}>
      <Select options={protocols} defaultValue="saml2" aria-label="Protocol" />
    </div>
  ),
};

export const WithDescriptions: Story = {
  render: () => (
    <div style={{ maxWidth: 420 }}>
      <Select
        defaultValue="combiconnect"
        aria-label="DigiD interface"
        options={[
          { value: "combiconnect", label: "CombiConnect", description: "DigiD + Machtigen, one koppelvlak" },
          { value: "classic", label: "Classic DigiD SAML v3.x", description: "Citizen authentication only" },
          { value: "eid-stelsel", label: "eID-stelsel", description: "BVD routing across eID means" },
        ]}
      />
    </div>
  ),
};

export const Disabled: Story = {
  render: () => (
    <div style={{ maxWidth: 380 }}>
      <Select options={protocols} defaultValue="oidc" disabled aria-label="Protocol" />
    </div>
  ),
};
