import type { Meta, StoryObj } from "@storybook/react";
import { ProviderLogo, ProviderKind } from "./ProviderLogo";

const meta: Meta<typeof ProviderLogo> = { title: "Identity/ProviderLogo", component: ProviderLogo };
export default meta;
type Story = StoryObj<typeof ProviderLogo>;

const kinds: ProviderKind[] = ["oidc", "saml", "ldap", "social", "digid", "eherkenning", "eidas", "google", "microsoft", "github"];

export const All: Story = {
  render: () => (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "1.2rem" }}>
      {kinds.map((k) => (
        <div key={k} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: ".4rem", width: 84 }}>
          <ProviderLogo kind={k} size={44} />
          <span style={{ fontSize: ".75rem", color: "var(--fg-muted)" }}>{k}</span>
        </div>
      ))}
    </div>
  ),
};
