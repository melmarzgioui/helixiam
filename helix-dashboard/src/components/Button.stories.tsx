/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { Button } from "./Button";

const meta: Meta<typeof Button> = {
  title: "Components/Button",
  component: Button,
  args: { children: "Add identity provider" },
  argTypes: {
    variant: { control: "inline-radio", options: ["primary", "ghost"] },
    size: { control: "inline-radio", options: ["md", "lg"] },
    block: { control: "boolean" },
  },
};
export default meta;

type Story = StoryObj<typeof Button>;

export const Primary: Story = { args: { variant: "primary" } };
export const Ghost: Story = { args: { variant: "ghost" } };
export const Large: Story = { args: { variant: "primary", size: "lg" } };
export const Block: Story = { args: { variant: "primary", block: true } };
export const Disabled: Story = { args: { variant: "primary", disabled: true } };
