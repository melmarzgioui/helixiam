/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Helix IAM (6) Self-service Account: pure form validators for the account surface — kept side-effect-free so
 * they are unit-testable and reused by both the change-password and profile forms (block submit + show inline
 * errors; never let an empty required field through).
 */

export interface ChangePasswordFields {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export type ChangePasswordErrors = Partial<Record<keyof ChangePasswordFields, string>>;

/** Validate the change-password form. Empty object ⇒ valid. */
export function validateChangePassword(fields: ChangePasswordFields): ChangePasswordErrors {
  const errors: ChangePasswordErrors = {};
  if (!fields.currentPassword.trim()) {
    errors.currentPassword = "Enter your current password.";
  }
  if (!fields.newPassword) {
    errors.newPassword = "Enter a new password.";
  } else if (fields.newPassword.length < 8) {
    errors.newPassword = "Use at least 8 characters.";
  } else if (fields.newPassword === fields.currentPassword) {
    errors.newPassword = "The new password must differ from the current one.";
  }
  if (fields.confirmPassword !== fields.newPassword) {
    errors.confirmPassword = "Passwords do not match.";
  }
  return errors;
}

/** A simple, permissive email check (matches the backend's @Email leniency). Blank is allowed (no email). */
export function validateEmail(email: string): string | undefined {
  const trimmed = email.trim();
  if (!trimmed) {
    return undefined;
  }
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed) ? undefined : "Enter a valid email address.";
}

/** Whether an errors object is empty (form may submit). */
export function isValid(errors: Record<string, string | undefined>): boolean {
  return Object.values(errors).every((v) => !v);
}
