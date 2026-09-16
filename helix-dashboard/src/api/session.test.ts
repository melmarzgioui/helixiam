/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { consoleBaseUrl } from "./session";

describe("session base url", () => {
  it("derives the console base from window.location.origin", () => {
    // @ts-expect-error stub location
    globalThis.window = { location: { origin: "http://localhost:8180", assign() {} } };
    expect(consoleBaseUrl()).toBe("http://localhost:8180");
  });
});
