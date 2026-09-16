/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { Modal, ConfirmDialog } from "./Modal";
import { Button } from "./Button";
import { FormField, Input } from "./FormField";

const meta: Meta = { title: "Components/Modal" };
export default meta;
type Story = StoryObj;

export const EditConnection: Story = {
  render: () => {
    const [open, setOpen] = React.useState(true);
    return (
      <>
        <Button onClick={() => setOpen(true)}>Open modal</Button>
        <Modal
          open={open}
          title="Rename connection"
          onClose={() => setOpen(false)}
          footer={
            <>
              <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <Button variant="primary" onClick={() => setOpen(false)}>Save</Button>
            </>
          }
        >
          <FormField label="Display name" required>
            <Input defaultValue="DigiD (CombiConnect)" />
          </FormField>
        </Modal>
      </>
    );
  },
};

export const Confirm: Story = {
  render: () => {
    const [open, setOpen] = React.useState(true);
    return (
      <>
        <Button onClick={() => setOpen(true)}>Delete…</Button>
        <ConfirmDialog
          open={open}
          title="Delete connection?"
          message="Removing “DigiD (CombiConnect)” will sign out users who rely on it. This cannot be undone."
          onConfirm={() => setOpen(false)}
          onCancel={() => setOpen(false)}
        />
      </>
    );
  },
};
