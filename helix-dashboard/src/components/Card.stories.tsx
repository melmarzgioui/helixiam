/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { Card } from "./Card";
import { Badge } from "./Badge";
import { Button } from "./Button";

const meta: Meta<typeof Card> = {
  title: "Components/Card",
  component: Card,
};
export default meta;

type Story = StoryObj<typeof Card>;

export const IdentityProvider: Story = {
  render: () => (
    <div style={{ maxWidth: 520 }}>
      <Card
        title="DigiD (CombiConnect)"
        subtitle="SAML2 · BSN · LoA Substantieel"
        actions={<Badge tone="success">Enabled</Badge>}
      >
        <p style={{ margin: "0 0 1rem", color: "var(--fg-muted)" }}>
          Citizen login via Logius. Subject delivered as an EncryptedID; AuthnRequest over HTTP-POST,
          enveloped-signed with the SP key.
        </p>
        <Button variant="ghost">Edit connection</Button>
      </Card>
    </div>
  ),
};
