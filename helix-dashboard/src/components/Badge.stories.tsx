/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { Badge } from "./Badge";

const meta: Meta<typeof Badge> = {
  title: "Components/Badge",
  component: Badge,
  args: { children: "Enabled" },
  argTypes: { tone: { control: "inline-radio", options: ["neutral", "success", "warning", "danger", "accent"] } },
};
export default meta;

type Story = StoryObj<typeof Badge>;

export const Success: Story = { args: { tone: "success", children: "Enabled" } };
export const Neutral: Story = { args: { tone: "neutral", children: "Draft" } };
export const Warning: Story = { args: { tone: "warning", children: "Metadata expiring" } };
export const Danger: Story = { args: { tone: "danger", children: "Error" } };
export const Loa: Story = { args: { tone: "accent", children: "LoA Substantieel" } };
