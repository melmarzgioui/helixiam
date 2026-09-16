import type { Meta, StoryObj } from "@storybook/react";
import { ProviderWizard } from "./ProviderWizard";

const meta: Meta<typeof ProviderWizard> = {
  title: "Identity/ProviderWizard",
  component: ProviderWizard,
};
export default meta;
type Story = StoryObj<typeof ProviderWizard>;

export const AddProvider: Story = {
  render: () => <ProviderWizard onComplete={(r) => console.log("create", r)} onCancel={() => {}} />,
};
