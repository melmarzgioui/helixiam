/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { MultiCombobox } from "./MultiCombobox";
import type { ComboOption } from "./Combobox";

const meta: Meta<typeof MultiCombobox> = {
  title: "Components/MultiCombobox",
  component: MultiCombobox,
};
export default meta;

type Story = StoryObj<typeof MultiCombobox>;

const roleOptions: ComboOption[] = [
  { value: "invoices:read", label: "invoices:read", group: "Realm roles" },
  { value: "reports:view", label: "reports:view", group: "Realm roles" },
  { value: "admin", label: "admin", group: "Realm roles" },
  { value: "billing-bot-client/ledger:write", label: "ledger:write", description: "billing-bot-client", group: "Client: billing-bot-client" },
  { value: "billing-bot-client/audit", label: "audit", description: "billing-bot-client", group: "Client: billing-bot-client" },
];

function Controlled({ initial = [] as string[] }) {
  const [values, setValues] = React.useState<string[]>(initial);
  return (
    <div style={{ maxWidth: 460 }}>
      <MultiCombobox values={values} onChange={setValues} options={roleOptions}
        placeholder="Add roles…" aria-label="Roles" />
      <p style={{ marginTop: 8, fontSize: ".8rem", color: "#888" }}>value: {values.join(" ") || "—"}</p>
    </div>
  );
}

export const Default: Story = { render: () => <Controlled /> };
export const Preselected: Story = { render: () => <Controlled initial={["invoices:read", "billing-bot-client/ledger:write"]} /> };
