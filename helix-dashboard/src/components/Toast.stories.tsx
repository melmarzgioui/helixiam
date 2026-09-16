import type { Meta, StoryObj } from "@storybook/react";
import { Toast } from "./Toast";

const meta: Meta<typeof Toast> = { title: "Components/Toast", component: Toast };
export default meta;
type Story = StoryObj<typeof Toast>;

export const Success: Story = { args: { tone: "success", title: "Connection saved", message: "DigiD (CombiConnect) is now enabled.", onDismiss: () => {} } };
export const Error: Story = { args: { tone: "error", title: "Metadata import failed", message: "Could not reach https://idp.example/metadata (HTTP 404).", onDismiss: () => {} } };
export const Info: Story = { args: { tone: "info", title: "Signing certificate rotates in 14 days", onDismiss: () => {} } };

export const Stack: Story = {
  render: () => (
    <div style={{ display: "flex", flexDirection: "column", gap: ".7rem" }}>
      <Toast tone="success" title="Connection saved" message="DigiD (CombiConnect) is now enabled." onDismiss={() => {}} />
      <Toast tone="info" title="Signing certificate rotates in 14 days" onDismiss={() => {}} />
      <Toast tone="error" title="Metadata import failed" message="HTTP 404 from the IdP." onDismiss={() => {}} />
    </div>
  ),
};
