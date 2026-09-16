/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import { Tooltip } from "./Tooltip";
import { Button } from "./Button";

const meta: Meta<typeof Tooltip> = { title: "Components/Tooltip", component: Tooltip };
export default meta;
type Story = StoryObj<typeof Tooltip>;

export const OnButton: Story = {
  render: () => (
    <div style={{ padding: "3rem 1rem" }}>
      <Tooltip content="LoA Substantieel maps to eIDAS substantial">
        <Button variant="ghost">Hover me</Button>
      </Tooltip>
    </div>
  ),
};
