/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { FieldContext, useFieldA11y, type FieldA11y } from "./fieldA11y";

export { useFieldA11y };

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;
export const Input = React.forwardRef<HTMLInputElement, InputProps>(function Input({ className, ...props }, ref) {
  const a11y = useFieldA11y(props);
  return <input ref={ref} className={["hx-input", className].filter(Boolean).join(" ")} {...props} {...a11y} />;
});

export type TextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement>;
export function Textarea({ className, ...props }: TextareaProps) {
  const a11y = useFieldA11y(props);
  return <textarea className={["hx-input", className].filter(Boolean).join(" ")} {...props} {...a11y} />;
}

export { Select } from "./Select";
export type { SelectProps, SelectOption } from "./Select";

export interface FormFieldProps {
  label: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  required?: boolean;
  /** Label a group of controls (tiles, buttons) instead of wrapping a single input in a <label>. */
  group?: boolean | "radiogroup";
  children: React.ReactNode;
}

/** Labelled form field with hint + error — the standard form row. Class-based (components.css). */
export function FormField({ label, hint, error, required, group, children }: FormFieldProps) {
  const labelId = React.useId();
  const hintId = React.useId();
  const errorId = React.useId();
  const showHint = !!hint && !error;
  const a11y: FieldA11y = {
    describedBy: [showHint ? hintId : null, error ? errorId : null].filter(Boolean).join(" ") || undefined,
    errorId: error ? errorId : undefined,
    invalid: !!error,
  };
  // The hint and error sit OUTSIDE the <label>, so they are not read as part of the control's name; the control
  // points at them with aria-describedby instead (see useFieldA11y).
  const messages = (
    <>
      {showHint && <span className="hx-field__hint" id={hintId}>{hint}</span>}
      {error && <span className="hx-field__error" id={errorId} role={group ? "alert" : undefined}>{error}</span>}
    </>
  );
  if (group) {
    // A group of controls (radio tiles, a secret's status + action buttons): a <label> would forward clicks to
    // its first button, so render a labelled group instead.
    return (
      <div className="hx-field" role={group === "radiogroup" ? "radiogroup" : "group"} aria-labelledby={labelId}
        aria-describedby={a11y.describedBy}>
        <span className="hx-field__label" id={labelId}>
          {label}
          {required && <span className="hx-field__req"> *</span>}
        </span>
        <FieldContext.Provider value={a11y}>{children}</FieldContext.Provider>
        {messages}
      </div>
    );
  }
  return (
    <div className="hx-field">
      <label className="hx-field__control">
        <span className="hx-field__label">
          {label}
          {required && <span className="hx-field__req"> *</span>}
        </span>
        <FieldContext.Provider value={a11y}>{children}</FieldContext.Provider>
      </label>
      {messages}
    </div>
  );
}
