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

/** Status pill — e.g. connector state (Enabled / Draft / Error) or LoA. */
export function Badge({ tone = "neutral", children }: BadgeProps) {
  return (
    <span className={`hx-badge hx-badge--${tone}`}>
      {children}
    </span>
  );
}
