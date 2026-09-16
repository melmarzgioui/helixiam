/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;
export function Input({ className, ...props }: InputProps) {
  return <input className={["hx-input", className].filter(Boolean).join(" ")} {...props} />;
}

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
  children: React.ReactNode;
}

/** Labelled form field with hint + error — the standard form row. Class-based (components.css). */
export function FormField({ label, hint, error, required, children }: FormFieldProps) {
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
