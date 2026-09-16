import type { Meta, StoryObj } from "@storybook/react";
import { Drawer } from "./Drawer";
import { Badge } from "./Badge";

const meta: Meta<typeof Drawer> = {
  title: "Components/Drawer",
  component: Drawer,
  args: { open: true, title: "Session details", onClose: () => {} },
};
export default meta;

type Story = StoryObj<typeof Drawer>;

export const SessionDetail: Story = {
  args: {
    children: (
      <>
        <div className="hx-drawer-field">
          <div className="hx-drawer-field-label">Type</div>
          <div className="hx-drawer-field-value"><Badge tone="neutral">User</Badge></div>
        </div>
        <div className="hx-drawer-field">
          <div className="hx-drawer-field-label">Identity</div>
          <div className="hx-drawer-field-value">admin</div>
          <div className="hx-drawer-mono">c1a848b2-cf68-45d5-85d1-97101cb702a8</div>
        </div>
        <div className="hx-drawer-field">
          <div className="hx-drawer-field-label">App</div>
          <div className="hx-drawer-field-value"><Badge tone="accent">helix-console</Badge></div>
        </div>
      </>
    ),
  },
};
