/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { createFlowHttpClient, FlowExecution } from "./flows";

describe("createFlowHttpClient", () => {
  afterEach(() => vi.restoreAllMocks());

  it("includes per-execution config in the save payload", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ realmId: "master", alias: "browser", builtIn: true, executions: [] }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const execs: FlowExecution[] = [
      { executionId: "e1", parentId: null, authenticatorId: "idp-redirect", requirement: "REQUIRED", condition: false, priority: 10, config: { providerAlias: "digid", mode: "REDIRECT" } },
    ];
    await createFlowHttpClient().saveByAlias("master", "browser", execs);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("PUT");
    const body = JSON.parse(init.body);
    expect(body.executions[0].config).toEqual({ providerAlias: "digid", mode: "REDIRECT" });
  });
});
