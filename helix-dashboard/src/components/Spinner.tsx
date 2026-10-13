/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface SpinnerProps {
  size?: number;
  label?: string;
}

/** Indeterminate spinner. Keyframes live in components.css (helix-spin). */
export function Spinner({ size = 20, label }: SpinnerProps) {
  return (
    <span className="hx-spinner-wrap">
      <span
        role="status"
        aria-label={label ?? "Loading"}
        className="hx-spinner-ring"
        // `size` is an open numeric prop; the border width is derived from it. Both are carried as
        // custom properties — a value CSS cannot itself compute.
        style={{ "--spin-size": `${size}px`, "--spin-border": `${Math.max(2, Math.round(size / 10))}px` } as React.CSSProperties}
      />
      {label && <span className="hx-spinner-label">{label}</span>}
    </span>
  );
}
