/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { ProviderLogo, ProviderKind } from "./ProviderLogo";

export interface ProviderTileProps {
  kind: ProviderKind;
  title: React.ReactNode;
  description?: React.ReactNode;
  selected?: boolean;
  disabled?: boolean;
  onSelect?: () => void;
  /** e.g. a LoaBadge or protocol tag shown top-right. */
  tag?: React.ReactNode;
}

/** Selectable provider tile — the building block of the wizard's provider picker. */
export function ProviderTile({ kind, title, description, selected, disabled, onSelect, tag }: ProviderTileProps) {
  return (
    <button
      type="button"
      role="radio"
      className="hx-tile hx-ptile"
      aria-checked={!!selected}
      disabled={disabled}
      onClick={onSelect}
    >
      <ProviderLogo kind={kind} />
      <span className="hx-ptile__text">
        <span className="hx-ptile__row">
          <span className="hx-ptile__title">{title}</span>
          {tag}
        </span>
        {description && (
          <span className="hx-ptile__desc">{description}</span>
        )}
      </span>
      {selected && (
        <span aria-hidden="true" className="hx-ptile__check">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" fill="currentColor" opacity="0.16" />
            <path d="M7 12.5l3 3 7-7" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </span>
      )}
    </button>
  );
}
