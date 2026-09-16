import type { Meta, StoryObj } from "@storybook/react";
import { FormField, Input, Select } from "./FormField";
import { Button } from "./Button";

const meta: Meta = {
  title: "Components/FormField",
};
export default meta;

type Story = StoryObj;

export const Text: Story = {
  render: () => (
    <div style={{ maxWidth: 460 }}>
      <FormField label="SP entity id" required hint="The AuthnRequest issuer + assertion audience.">
        <Input placeholder="https://helix.example/sp" />
      </FormField>
    </div>
  ),
};

export const WithError: Story = {
  render: () => (
    <div style={{ maxWidth: 460 }}>
      <FormField label="Metadata URL" required error="Could not fetch metadata (HTTP 404).">
        <Input defaultValue="https://idp.example/bad-metadata" />
      </FormField>
    </div>
  ),
};

export const DigidProfilePicker: Story = {
  name: "DigiD profile (Select)",
  render: () => (
    <div style={{ maxWidth: 460 }}>
      <FormField label="DigiD interface" required hint="Pick the koppelvlak your service is onboarded for.">
        <Select
          defaultValue="combiconnect"
          options={[
            { value: "combiconnect", label: "CombiConnect", description: "DigiD + Machtigen, one koppelvlak" },
            { value: "classic", label: "Classic DigiD SAML v3.x", description: "Citizen authentication only" },
            { value: "eid-stelsel", label: "eID-stelsel", description: "BVD routing across eID means" },
          ]}
        />
      </FormField>
      <Button variant="primary">Continue</Button>
    </div>
  ),
};
