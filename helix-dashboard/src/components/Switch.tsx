import React from "react";

export interface SwitchProps {
  checked?: boolean;
  defaultChecked?: boolean;
  onChange?: (checked: boolean) => void;
  disabled?: boolean;
  /** When set, renders a visible text label next to the switch AND names it for assistive tech. */
  label?: string;
  /** Accessible name for a switch whose visible label lives elsewhere (no inline text rendered). */
  ariaLabel?: string;
  /** id of an external element that labels this switch (preferred when a visible <label> exists —
   *  htmlFor does NOT associate a native label with a role="switch" button, so reference it here). */
  ariaLabelledby?: string;
  id?: string;
}

/** Toggle switch — the canonical "enable this connector" control. */
export function Switch({ checked, defaultChecked, onChange, disabled, label, ariaLabel, ariaLabelledby, id }: SwitchProps) {
  const isControlled = checked !== undefined;
  const [internal, setInternal] = React.useState(!!defaultChecked);
  const on = isControlled ? !!checked : internal;

  const toggle = () => {
    if (disabled) return;
    if (!isControlled) setInternal(!on);
    onChange?.(!on);
  };

  const control = (
    <button
      type="button"
      role="switch"
      id={id}
      className="hx-switch"
      aria-checked={on}
      aria-label={label ?? ariaLabel}
      aria-labelledby={ariaLabelledby}
      disabled={disabled}
      onClick={toggle}
    >
      <span className="hx-switch-thumb" />
    </button>
  );

  if (!label) return control;
  return (
    <label style={{ display: "inline-flex", alignItems: "center", gap: ".6rem", cursor: disabled ? "not-allowed" : "pointer" }}>
      {control}
      <span style={{ color: "var(--fg)", font: "500 .95rem var(--font)" }}>{label}</span>
    </label>
  );
}
