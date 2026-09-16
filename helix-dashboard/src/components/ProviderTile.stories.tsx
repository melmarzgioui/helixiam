import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { ProviderTile } from "./ProviderTile";
import { LoaBadge } from "./LoaBadge";
import { PROVIDER_TYPES } from "./providerCatalog";

const meta: Meta<typeof ProviderTile> = { title: "Identity/ProviderTile", component: ProviderTile };
export default meta;
type Story = StoryObj<typeof ProviderTile>;

export const Picker: Story = {
  render: () => {
    const [sel, setSel] = React.useState("digid");
    return (
      <div style={{ display: "grid", gap: ".7rem", maxWidth: 460 }}>
        {PROVIDER_TYPES.map((t) => (
          <ProviderTile
            key={t.id}
            kind={t.kind}
            title={t.name}
            description={t.description}
            selected={sel === t.id}
            onSelect={() => setSel(t.id)}
            tag={t.defaultLoa ? <LoaBadge level={t.defaultLoa} /> : undefined}
          />
        ))}
      </div>
    );
  },
};
