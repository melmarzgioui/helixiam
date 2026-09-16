/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { Switch } from "./Switch";

const meta: Meta<typeof Switch> = { title: "Components/Switch", component: Switch };
export default meta;
type Story = StoryObj<typeof Switch>;

export const On: Story = { args: { defaultChecked: true, label: "Connection enabled" } };
export const Off: Story = { args: { defaultChecked: false, label: "Connection enabled" } };
export const Disabled: Story = { args: { defaultChecked: true, disabled: true, label: "Locked by policy" } };
export const Bare: Story = { args: { defaultChecked: true } };
