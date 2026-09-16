import type { Meta, StoryObj } from "@storybook/react";
import { Spinner } from "./Spinner";

const meta: Meta<typeof Spinner> = { title: "Components/Spinner", component: Spinner };
export default meta;
type Story = StoryObj<typeof Spinner>;

export const Default: Story = { args: {} };
export const WithLabel: Story = { args: { label: "Importing metadata…" } };
export const Large: Story = { args: { size: 36 } };
