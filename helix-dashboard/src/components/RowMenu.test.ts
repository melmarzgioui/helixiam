/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { placeMenu } from "./RowMenu";

const VIEW = { width: 1000, height: 800 };

describe("placeMenu", () => {
  it("opens below the trigger when it fits", () => {
    expect(placeMenu({ top: 100, bottom: 130, right: 900 }, 200, VIEW)).toEqual({ top: 134, right: 100 });
  });
  it("flips above the trigger near the bottom of the viewport", () => {
    expect(placeMenu({ top: 700, bottom: 730, right: 900 }, 200, VIEW)).toEqual({ top: 496, right: 100 });
  });
  it("stays on screen when neither side fits", () => {
    const p = placeMenu({ top: 100, bottom: 130, right: 900 }, 790, VIEW);
    expect(p.top).toBeGreaterThanOrEqual(8);
  });
});
