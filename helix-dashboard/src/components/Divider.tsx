/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface DividerProps {
  label?: string;
  /** Vertical spacing (CSS length). */
  gap?: string;
}

/** Horizontal rule, optionally with a centered label. */
export function Divider({ label, gap }: DividerProps) {
  // `gap` is an open CSS-length prop; the kit default (1.25rem) lives in the CSS fallback, so a custom
  // property is only set when the caller overrides it.
  const gapVar = gap ? ({ "--divider-gap": gap } as React.CSSProperties) : undefined;
  if (!label) {
    return <hr className="hx-divider" style={gapVar} />;
  }
  return (
    <div className="hx-divider-row" style={gapVar}>
      <span className="hx-divider-row__line" />
      <span className="hx-divider-row__label">
        {label}
      </span>
      <span className="hx-divider-row__line" />
    </div>
  );
}
