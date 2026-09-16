/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

export interface SpinnerProps {
  size?: number;
  label?: string;
}

/** Indeterminate spinner. Keyframes are injected once. */
export function Spinner({ size = 20, label }: SpinnerProps) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: ".5rem" }}>
      <style>{"@keyframes helix-spin{to{transform:rotate(360deg)}}"}</style>
      <span
        role="status"
        aria-label={label ?? "Loading"}
        style={{
          width: size,
          height: size,
          borderRadius: "50%",
          border: `${Math.max(2, Math.round(size / 10))}px solid var(--border)`,
          borderTopColor: "var(--primary)",
          animation: "helix-spin .7s linear infinite",
          display: "inline-block",
        }}
      />
      {label && <span style={{ color: "var(--fg-muted)", font: "500 .9rem var(--font)" }}>{label}</span>}
    </span>
  );
}
