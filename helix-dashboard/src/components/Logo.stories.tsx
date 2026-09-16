/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { Logo } from "./Logo";

const meta: Meta<typeof Logo> = {
  title: "Brand/Logo",
  component: Logo,
  argTypes: {
    variant: { control: "inline-radio", options: ["lockup", "wordmark", "mark"] },
    size: { control: "inline-radio", options: ["sm", "md", "lg"] },
  },
};
export default meta;

type Story = StoryObj<typeof Logo>;

export const Lockup: Story = { args: { variant: "lockup", size: "lg" } };
export const Wordmark: Story = { args: { variant: "wordmark", size: "lg" } };
export const MarkOnly: Story = { args: { variant: "mark", size: "lg" } };

export const Sizes: Story = {
  render: () => (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem", alignItems: "flex-start" }}>
      <Logo size="sm" />
      <Logo size="md" />
      <Logo size="lg" />
    </div>
  ),
};
