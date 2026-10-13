/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactElement;
  side?: "top" | "bottom";
}

/** Lightweight hover/focus tooltip. */
export function Tooltip({ content, children, side = "top" }: TooltipProps) {
  const [open, setOpen] = React.useState(false);
  return (
    <span
      className="hx-tooltip-root"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && (
        <span
          role="tooltip"
          className={`hx-tooltip-bubble hx-tooltip-bubble--${side === "top" ? "top" : "bottom"}`}
        >
          {content}
        </span>
      )}
    </span>
  );
}
