import React from "react";

export interface StepperProps {
  steps: string[];
  /** Zero-based index of the current step. */
  current: number;
}

/** Horizontal step indicator — drives the E8.4 "Add identity provider" wizard. */
export function Stepper({ steps, current }: StepperProps) {
  return (
    <ol style={{ display: "flex", alignItems: "center", gap: ".5rem", listStyle: "none", margin: 0, padding: 0 }}>
      {steps.map((label, i) => {
        const done = i < current;
        const active = i === current;
        const circleBg = done ? "var(--primary)" : active ? "var(--bg)" : "var(--bg)";
        const circleBorder = done || active ? "var(--primary)" : "var(--border-strong)";
        const circleColor = done ? "#fff" : active ? "var(--primary)" : "var(--fg-faint)";
        return (
          <React.Fragment key={label}>
            <li style={{ display: "inline-flex", alignItems: "center", gap: ".5rem" }} aria-current={active ? "step" : undefined}>
              <span
                style={{
                  width: 26,
                  height: 26,
                  flexShrink: 0,
                  borderRadius: "50%",
                  border: `2px solid ${circleBorder}`,
                  background: circleBg,
                  color: circleColor,
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  font: "700 .8rem var(--font)",
                }}
              >
                {done ? (
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M5 13l4 4L19 7" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                ) : (
                  i + 1
                )}
              </span>
              <span className="hx-step-label" style={{ font: `${active ? 600 : 500} .9rem var(--font)`, color: active || done ? "var(--fg)" : "var(--fg-faint)", whiteSpace: "nowrap" }}>
                {label}
              </span>
            </li>
            {i < steps.length - 1 && <span style={{ flex: 1, minWidth: 18, borderTop: `2px solid ${i < current ? "var(--primary)" : "var(--border)"}` }} />}
          </React.Fragment>
        );
      })}
    </ol>
  );
}
