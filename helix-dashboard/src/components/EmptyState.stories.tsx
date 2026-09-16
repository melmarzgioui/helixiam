/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { EmptyState } from "./EmptyState";
import { Button } from "./Button";

const meta: Meta<typeof EmptyState> = { title: "Components/EmptyState", component: EmptyState };
export default meta;
type Story = StoryObj<typeof EmptyState>;

export const NoProviders: Story = {
  render: () => (
    <div style={{ maxWidth: 560 }}>
      <EmptyState
        title="No identity providers yet"
        message="Connect DigiD, eHerkenning, eIDAS, or any OIDC/SAML provider so users can sign in through it."
        action={<Button variant="primary">Add identity provider</Button>}
      />
    </div>
  ),
};
