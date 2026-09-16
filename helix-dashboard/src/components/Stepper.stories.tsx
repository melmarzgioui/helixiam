import type { Meta, StoryObj } from "@storybook/react";
import { Stepper } from "./Stepper";

const meta: Meta<typeof Stepper> = { title: "Components/Stepper", component: Stepper };
export default meta;
type Story = StoryObj<typeof Stepper>;

const steps = ["Protocol", "Connection", "Mappers", "Review"];

export const Step1: Story = { args: { steps, current: 0 } };
export const Step3: Story = { args: { steps, current: 2 } };
export const Complete: Story = { args: { steps, current: 4 } };
