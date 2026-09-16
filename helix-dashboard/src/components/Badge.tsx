/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "accent";

export interface BadgeProps {
  tone?: BadgeTone;
  children: React.ReactNode;
}

const tones: Record<BadgeTone, React.CSSProperties> = {
  neutral: { background: "var(--surface)", color: "var(--fg-muted)", borderColor: "var(--border)" },
  success: { background: "var(--kd-jade-soft)", color: "var(--kd-cucumber-d)", borderColor: "var(--kd-jade)" },
  warning: { background: "#fdf3e7", color: "#8a5a12", borderColor: "#f0d9b5" },
  danger: { background: "#fdecec", color: "#9a2b2b", borderColor: "#f1c9c9" },
  accent: { background: "var(--kd-jade-soft)", color: "var(--kd-cucumber)", borderColor: "var(--kd-jade)" },
};

/** Status pill — e.g. connector state (Enabled / Draft / Error) or LoA. */
export function Badge({ tone = "neutral", children }: BadgeProps) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: ".35rem",
        padding: ".2rem .6rem",
        borderRadius: "999px",
        border: "1px solid",
        font: "600 .8rem var(--font)",
        ...tones[tone],
      }}
    >
      {children}
    </span>
  );
}
