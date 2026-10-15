/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ToastProvider } from "../components/ToastProvider";
import { LocaleProvider } from "../i18n/LocaleContext";
import { createTrustedListMemoryClient, sampleTrustedList, type TrustedListApi } from "../api/trustedLists";
import { TrustedListDetailPage } from "./TrustedListsPage";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

async function flush() {
  for (let i = 0; i < 5; i++) {
    await act(async () => { await Promise.resolve(); });
  }
}

function button(label: string): HTMLButtonElement {
  const b = [...container.querySelectorAll("button")].find((x) => x.textContent?.trim() === label);
  if (!b) throw new Error(`no button ${label}`);
  return b as HTMLButtonElement;
}

async function render(api: TrustedListApi) {
  act(() => root.render(
    <LocaleProvider initialLocale="en">
      <ToastProvider>
        <TrustedListDetailPage api={api} realmId="master" id="tl-1" onBack={() => undefined} />
      </ToastProvider>
    </LocaleProvider>,
  ));
  await flush();
}

describe("TrustedListDetailPage", () => {
  it("tells the admin when someone else changed the list, and reloads it on request", async () => {
    const api = createTrustedListMemoryClient({ lists: [sampleTrustedList({ configVersion: 3 })] });
    await render(api);
    // another admin saves first
    const other = await api.get("master", "tl-1");
    await api.update("master", "tl-1", { ...other, graceHours: 48, configVersion: other.configVersion });

    await act(async () => { button("Save settings").click(); });
    await flush();

    expect(container.textContent).toContain("This trusted list was changed by someone else");
    await act(async () => { button("Reload").click(); });
    await flush();
    expect(container.textContent).not.toContain("This trusted list was changed by someone else");
    expect((container.querySelector("input[inputmode=numeric]") as HTMLInputElement).value).toBe("48");
  });

  it("explains that a list in use cannot be deleted", async () => {
    const api = createTrustedListMemoryClient({ lists: [sampleTrustedList()], usedBy: { "tl-1": ["eudi-wallet"] } });
    await render(api);

    await act(async () => { button("Delete").click(); });
    await flush();
    const confirm = [...document.querySelectorAll("button")].filter((b) => b.textContent?.trim() === "Delete").pop()!;
    await act(async () => { confirm.click(); });
    await flush();

    expect(container.textContent).toContain("used by eudi-wallet");
  });
});
