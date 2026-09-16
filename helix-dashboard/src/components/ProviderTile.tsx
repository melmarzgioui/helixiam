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
      className="hx-tile"
      aria-checked={!!selected}
      disabled={disabled}
      onClick={onSelect}
      style={{ position: "relative" }}
    >
      <ProviderLogo kind={kind} />
      <span style={{ flex: 1, minWidth: 0 }}>
        <span style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: ".5rem" }}>
          <span style={{ font: "600 1rem var(--font)", color: "var(--fg)" }}>{title}</span>
          {tag}
        </span>
        {description && (
          <span style={{ display: "block", marginTop: ".25rem", fontSize: ".85rem", color: "var(--fg-muted)" }}>{description}</span>
        )}
      </span>
      {selected && (
        <span aria-hidden="true" style={{ position: "absolute", top: 10, right: 10, color: "var(--accent)", display: "flex" }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" fill="currentColor" opacity="0.16" />
            <path d="M7 12.5l3 3 7-7" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </span>
      )}
    </button>
  );
}
