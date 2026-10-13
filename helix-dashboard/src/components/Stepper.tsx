/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface StepperProps {
  steps: string[];
  /** Zero-based index of the current step. */
  current: number;
}

/** Horizontal step indicator — drives the E8.4 "Add identity provider" wizard. */
export function Stepper({ steps, current }: StepperProps) {
  return (
    <ol className="hx-stepper">
      {steps.map((label, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <React.Fragment key={label}>
            <li className="hx-stepper__item" aria-current={active ? "step" : undefined}>
              <span className={`hx-stepper__circle${done ? " hx-stepper__circle--done" : active ? " hx-stepper__circle--active" : ""}`}>
                {done ? (
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M5 13l4 4L19 7" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                ) : (
                  i + 1
                )}
              </span>
              <span className={`hx-step-label hx-stepper__label${active ? " hx-stepper__label--active" : done ? " hx-stepper__label--done" : ""}`}>
                {label}
              </span>
            </li>
            {i < steps.length - 1 && <span className={`hx-stepper__connector${i < current ? " hx-stepper__connector--done" : ""}`} />}
          </React.Fragment>
        );
      })}
    </ol>
  );
}
