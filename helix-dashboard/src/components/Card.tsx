/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface CardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
}

/** Surface card per BRANDBOOK_KUBEDNA_V2 — radius --r, hairline border, soft shadow. Class-based (components.css). */
export function Card({ title, subtitle, actions, children, className }: CardProps) {
  const hasHead = title || actions;
  return (
    <section className={["hx-cardbox", "hx-surface", className].filter(Boolean).join(" ")}>
      {hasHead && (
        <header className="hx-cardbox__head">
          <div>
            {title && <h3 className="hx-cardbox__title">{title}</h3>}
            {subtitle && <p className="hx-cardbox__subtitle">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children && <div className={hasHead ? "hx-cardbox__body" : "hx-cardbox__body hx-cardbox__body--flush"}>{children}</div>}
    </section>
  );
}
