import type { Meta, StoryObj } from "@storybook/react";
import { LoaBadge } from "./LoaBadge";

const meta: Meta<typeof LoaBadge> = { title: "Identity/LoaBadge", component: LoaBadge };
export default meta;
type Story = StoryObj<typeof LoaBadge>;

export const Levels: Story = {
  render: () => (
    <div style={{ display: "flex", gap: ".6rem", flexWrap: "wrap" }}>
      <LoaBadge level="low" />
      <LoaBadge level="substantial" />
      <LoaBadge level="high" />
      <LoaBadge level="substantial" label="eIDAS substantial" />
    </div>
  ),
};
