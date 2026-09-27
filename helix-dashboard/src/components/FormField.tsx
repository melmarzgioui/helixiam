/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;
export const Input = React.forwardRef<HTMLInputElement, InputProps>(function Input({ className, ...props }, ref) {
  return <input ref={ref} className={["hx-input", className].filter(Boolean).join(" ")} {...props} />;
});

export type TextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement>;
export function Textarea({ className, ...props }: TextareaProps) {
  return <textarea className={["hx-input", className].filter(Boolean).join(" ")} {...props} />;
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
  if (group) {
    // A group of controls (radio tiles, a secret's status + action buttons): a <label> would forward clicks to
    // its first button, so render a labelled group instead.
    return (
      <div className="hx-field" role={group === "radiogroup" ? "radiogroup" : "group"} aria-labelledby={labelId}>
        <span className="hx-field__label" id={labelId}>
          {label}
          {required && <span className="hx-field__req"> *</span>}
        </span>
        {children}
        {hint && !error && <span className="hx-field__hint">{hint}</span>}
        {error && <span className="hx-field__error" role="alert">{error}</span>}
      </div>
    );
  }
  return (
    <label className="hx-field">
      <span className="hx-field__label">
        {label}
        {required && <span className="hx-field__req"> *</span>}
      </span>
      {children}
      {hint && !error && <span className="hx-field__hint">{hint}</span>}
      {error && <span className="hx-field__error">{error}</span>}
    </label>
  );
}
