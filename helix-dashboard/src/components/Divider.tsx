/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

export interface DividerProps {
  label?: string;
  /** Vertical spacing (CSS length). */
  gap?: string;
}

/** Horizontal rule, optionally with a centered label. */
export function Divider({ label, gap = "1.25rem" }: DividerProps) {
  if (!label) {
    return <hr style={{ border: 0, borderTop: "1px solid var(--border)", margin: `${gap} 0` }} />;
  }
  return (
    <div style={{ display: "flex", alignItems: "center", gap: ".8rem", margin: `${gap} 0` }}>
      <span style={{ flex: 1, borderTop: "1px solid var(--border)" }} />
      <span style={{ color: "var(--fg-faint)", font: "600 .75rem var(--font)", letterSpacing: ".06em", textTransform: "uppercase" }}>
        {label}
      </span>
      <span style={{ flex: 1, borderTop: "1px solid var(--border)" }} />
    </div>
  );
}
