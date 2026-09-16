/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export type AlertTone = "info" | "success" | "warning" | "danger";

export interface AlertProps {
  tone?: AlertTone;
  title?: React.ReactNode;
  children?: React.ReactNode;
  /** Optional dismiss handler — renders a close affordance when provided. */
  onDismiss?: () => void;
  className?: string;
}

const GLYPH: Record<AlertTone, React.ReactNode> = {
  info: <path d="M12 11v6M12 7.5v.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />,
  success: <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />,
  warning: <path d="M12 9v4M12 16.5v.01M12 3l9 16H3z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
  danger: <path d="M12 8v5M12 16.5v.01M12 3l9 16H3z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
};

/**
 * Inline status banner — the ONE way to show error / warning / info / success on a page (Toast is for
 * transient notifications). Class-based (`hx-alert hx-alert--{tone}`) so tone colours come from tokens.
 */
export function Alert({ tone = "info", title, children, onDismiss, className }: AlertProps) {
  return (
    <div className={["hx-alert", `hx-alert--${tone}`, className].filter(Boolean).join(" ")} role={tone === "danger" ? "alert" : "status"}>
      <svg className="hx-alert__icon" width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        {GLYPH[tone]}
      </svg>
      <div className="hx-alert__body">
        {title && <div className="hx-alert__title">{title}</div>}
        {children && <div className="hx-alert__text">{children}</div>}
      </div>
      {onDismiss && (
        <button type="button" className="hx-alert__x" aria-label="Dismiss" onClick={onDismiss}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </button>
      )}
    </div>
  );
}
