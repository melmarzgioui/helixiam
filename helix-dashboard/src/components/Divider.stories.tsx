import type { Meta, StoryObj } from "@storybook/react";
import { Divider } from "./Divider";

const meta: Meta<typeof Divider> = { title: "Components/Divider", component: Divider };
export default meta;
type Story = StoryObj<typeof Divider>;

export const Plain: Story = {
  render: () => (
    <div style={{ maxWidth: 420 }}>
      <p style={{ margin: 0, color: "var(--fg-muted)" }}>Above</p>
      <Divider />
      <p style={{ margin: 0, color: "var(--fg-muted)" }}>Below</p>
    </div>
  ),
};

export const Labelled: Story = {
  render: () => (
    <div style={{ maxWidth: 420 }}>
      <p style={{ margin: 0, color: "var(--fg-muted)" }}>Username &amp; password</p>
      <Divider label="or" />
      <p style={{ margin: 0, color: "var(--fg-muted)" }}>Continue with DigiD</p>
    </div>
  ),
};
