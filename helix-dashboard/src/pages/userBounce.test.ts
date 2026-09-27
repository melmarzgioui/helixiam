/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { emailBounce } from "./userBounce";

describe("emailBounce", () => {
  it("is null for a user whose address has not bounced (or an older server without the field)", () => {
    expect(emailBounce({ emailBounced: false, emailBouncedAt: null })).toBeNull();
    expect(emailBounce({})).toBeNull();
  });

  it("formats when the address bounced", () => {
    const at = Date.UTC(2026, 6, 3, 13, 20);
    const b = emailBounce({ emailBounced: true, emailBouncedAt: at });
    expect(b?.when).toMatch(/3 Jul 2026/);
    expect(emailBounce({ emailBounced: true, emailBouncedAt: at }, "nl")?.when).toMatch(/3 jul 2026/);
  });

  it("still reports the bounce without a time", () => {
    expect(emailBounce({ emailBounced: true, emailBouncedAt: null })).toEqual({ when: null });
    expect(emailBounce({ emailBounced: true })).toEqual({ when: null });
  });
});
