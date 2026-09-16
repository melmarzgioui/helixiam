/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { Checkbox, Radio, RadioCard } from "./Choice";

const meta: Meta = { title: "Components/Choice" };
export default meta;
type Story = StoryObj;

export const Checkboxes: Story = {
  render: () => (
    <div style={{ display: "flex", flexDirection: "column", gap: ".7rem" }}>
      <Checkbox defaultChecked label="email" />
      <Checkbox label="given_name" />
      <Checkbox defaultChecked disabled label="sub (required)" />
    </div>
  ),
};

export const Radios: Story = {
  render: () => (
    <div style={{ display: "flex", flexDirection: "column", gap: ".7rem" }}>
      <Radio defaultChecked label="HTTP-POST binding" />
      <Radio label="HTTP-Redirect binding" />
    </div>
  ),
};

export const Cards: Story = {
  render: () => (
    <div style={{ display: "grid", gap: ".7rem", maxWidth: 420 }}>
      <RadioCard selected title="OpenID Connect" description="Discovery, PKCE, refresh tokens" />
      <RadioCard title="SAML 2.0 (SP)" description="Metadata import, signed assertions" />
      <RadioCard title="DigiD (CombiConnect)" description="BSN via EncryptedID, LoA Substantieel" />
    </div>
  ),
};
