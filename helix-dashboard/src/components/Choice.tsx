/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface CheckProps {
  checked?: boolean;
  defaultChecked?: boolean;
  onChange?: (checked: boolean) => void;
  disabled?: boolean;
  label?: React.ReactNode;
  name?: string;
  value?: string;
}

function Row({ disabled, label, children }: { disabled?: boolean; label?: React.ReactNode; children: React.ReactNode }) {
  return (
    <label style={{ display: "inline-flex", alignItems: "center", gap: ".55rem", cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.55 : 1 }}>
      {children}
      {label && <span style={{ color: "var(--fg)", font: "400 .95rem var(--font)" }}>{label}</span>}
    </label>
  );
}

/** Checkbox — multi-select (e.g. attribute mappers to import). */
export function Checkbox({ checked, defaultChecked, onChange, disabled, label }: CheckProps) {
  const isControlled = checked !== undefined;
  const [internal, setInternal] = React.useState(!!defaultChecked);
  const on = isControlled ? !!checked : internal;
  const toggle = () => {
    if (disabled) return;
    if (!isControlled) setInternal(!on);
    onChange?.(!on);
  };
  return (
    <Row disabled={disabled} label={label}>
      <button
        type="button"
        role="checkbox"
        className="hx-check hx-check--box"
        aria-checked={on}
        disabled={disabled}
        onClick={toggle}
        style={{ cursor: "inherit" }}
      >
        {on && (
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M5 13l4 4L19 7" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        )}
      </button>
    </Row>
  );
}

/** Radio — single-select within a group. */
export function Radio({ checked, defaultChecked, onChange, disabled, label }: CheckProps) {
  const isControlled = checked !== undefined;
  const [internal, setInternal] = React.useState(!!defaultChecked);
  const on = isControlled ? !!checked : internal;
  const select = () => {
    if (disabled) return;
    if (!isControlled) setInternal(true);
    onChange?.(true);
  };
  return (
    <Row disabled={disabled} label={label}>
      <button
        type="button"
        role="radio"
        className="hx-check hx-check--radio"
        aria-checked={on}
        disabled={disabled}
        onClick={select}
        style={{ cursor: "inherit" }}
      >
        {on && <span style={{ width: 10, height: 10, borderRadius: "50%", background: "var(--primary)" }} />}
      </button>
    </Row>
  );
}

export interface RadioCardProps {
  selected?: boolean;
  onSelect?: () => void;
  disabled?: boolean;
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: React.ReactNode;
  /**
   * Part of a radio group that behaves as one tab stop: only the selected card is tabbable, and the arrow keys move
   * to (and select) the previous or next card, as for native radio buttons. Needs a selected card in the group.
   */
  roving?: boolean;
}

/** Arrow-key navigation between the enabled radio cards that share this card's parent. */
function moveInGroup(e: React.KeyboardEvent<HTMLButtonElement>) {
  const delta = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
  if (!delta) return;
  const parent = e.currentTarget.parentElement;
  if (!parent) return;
  const cards = Array.from(parent.querySelectorAll<HTMLButtonElement>(':scope > [role="radio"]:not(:disabled)'));
  const at = cards.indexOf(e.currentTarget);
  if (at < 0 || cards.length < 2) return;
  e.preventDefault();
  const next = cards[(at + delta + cards.length) % cards.length];
  next.focus();
  next.click();
}

export function RadioCard({ selected, onSelect, disabled, title, description, icon, roving }: RadioCardProps) {
  return (
    <button type="button" role="radio" className="hx-tile" aria-checked={!!selected} disabled={disabled} onClick={onSelect}
      tabIndex={roving ? (selected ? 0 : -1) : undefined} onKeyDown={roving ? moveInGroup : undefined}>
      {icon && <span className="hx-tile__icon">{icon}</span>}
      <span className="hx-tile__text">
        <span className="hx-tile__title">{title}</span>
        {description && <span className="hx-tile__desc">{description}</span>}
      </span>
    </button>
  );
}
