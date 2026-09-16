/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { isValid, validateChangePassword, validateEmail } from "./validation";

describe("validateChangePassword", () => {
  const base = { currentPassword: "old-secret", newPassword: "new-secret-9", confirmPassword: "new-secret-9" };

  it("passes a well-formed change", () => {
    expect(isValid(validateChangePassword(base))).toBe(true);
  });

  it("requires the current password", () => {
    expect(validateChangePassword({ ...base, currentPassword: "  " }).currentPassword).toBeTruthy();
  });

  it("requires a new password and a minimum length", () => {
    expect(validateChangePassword({ ...base, newPassword: "", confirmPassword: "" }).newPassword).toBeTruthy();
    expect(validateChangePassword({ ...base, newPassword: "short", confirmPassword: "short" }).newPassword).toBeTruthy();
  });

  it("rejects reusing the current password", () => {
    const same = { currentPassword: "old-secret", newPassword: "old-secret", confirmPassword: "old-secret" };
    expect(validateChangePassword(same).newPassword).toBeTruthy();
  });

  it("requires the confirmation to match", () => {
    expect(validateChangePassword({ ...base, confirmPassword: "different" }).confirmPassword).toBeTruthy();
  });
});

describe("validateEmail", () => {
  it("allows a blank email (no email is valid)", () => {
    expect(validateEmail("")).toBeUndefined();
    expect(validateEmail("   ")).toBeUndefined();
  });
  it("accepts a valid address and rejects garbage", () => {
    expect(validateEmail("a@b.co")).toBeUndefined();
    expect(validateEmail("not-an-email")).toBeTruthy();
  });
});

describe("isValid", () => {
  it("is true only when every field is error-free", () => {
    expect(isValid({ a: undefined, b: undefined })).toBe(true);
    expect(isValid({ a: undefined, b: "boom" })).toBe(false);
  });
});
