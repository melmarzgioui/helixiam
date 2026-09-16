import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Combobox, type ComboOption } from "./Combobox";

const meta: Meta<typeof Combobox> = {
  title: "Components/Combobox",
  component: Combobox,
};
export default meta;

type Story = StoryObj<typeof Combobox>;

const users: ComboOption[] = [
  { value: "alice@acme.example", label: "Alice Adams", description: "alice@acme.example" },
  { value: "bob@acme.example", label: "Bob Brown", description: "bob@acme.example" },
  { value: "carol@acme.example", label: "Carol Clark", description: "carol@acme.example" },
  { value: "dave@acme.example", label: "Dave Davis", description: "dave@acme.example" },
];

function Controlled({ allowCustom, initial = "" }: { allowCustom?: boolean; initial?: string }) {
  const [value, setValue] = React.useState(initial);
  return (
    <div style={{ maxWidth: 420 }}>
      <Combobox value={value} onChange={setValue} options={users} allowCustom={allowCustom}
        placeholder="Search a user…" aria-label="Owner" />
      <p style={{ marginTop: 8, fontSize: ".8rem", color: "#888" }}>value: {value || "—"}</p>
    </div>
  );
}

export const Default: Story = { render: () => <Controlled /> };
export const Preselected: Story = { render: () => <Controlled initial="bob@acme.example" /> };
export const AllowsCustomEntry: Story = { render: () => <Controlled allowCustom /> };
export const Loading: Story = {
  render: () => (
    <div style={{ maxWidth: 420 }}>
      <Combobox value="" onChange={() => {}} options={[]} loading placeholder="Search…" aria-label="Owner" />
    </div>
  ),
};
