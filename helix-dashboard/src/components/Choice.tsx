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
}

/** RadioCard — a selectable tile; the building block of the protocol/provider picker. */
export function RadioCard({ selected, onSelect, disabled, title, description, icon }: RadioCardProps) {
  return (
    <button type="button" role="radio" className="hx-tile" aria-checked={!!selected} disabled={disabled} onClick={onSelect}>
      {icon && <span style={{ flexShrink: 0, marginTop: 1 }}>{icon}</span>}
      <span>
        <span style={{ display: "block", font: "600 1rem var(--font)", color: "var(--fg)" }}>{title}</span>
        {description && (
          <span style={{ display: "block", marginTop: ".2rem", fontSize: ".85rem", color: "var(--fg-muted)" }}>{description}</span>
        )}
      </span>
    </button>
  );
}
