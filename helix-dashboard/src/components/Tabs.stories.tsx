import type { Meta, StoryObj } from "@storybook/react";
import { Tabs } from "./Tabs";

const meta: Meta<typeof Tabs> = { title: "Components/Tabs", component: Tabs };
export default meta;
type Story = StoryObj<typeof Tabs>;

export const ConnectionSections: Story = {
  render: () => (
    <div style={{ maxWidth: 560 }}>
      <Tabs
        defaultValue="settings"
        tabs={[
          { id: "settings", label: "Settings" },
          { id: "mappers", label: "Attribute mappers" },
          { id: "metadata", label: "Metadata" },
          { id: "advanced", label: "Advanced" },
        ]}
      />
    </div>
  ),
};
