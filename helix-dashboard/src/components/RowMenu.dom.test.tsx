/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// @vitest-environment jsdom

import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { RowMenu } from "./RowMenu";
import { Modal } from "./Modal";

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

function Harness() {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <RowMenu ariaLabel="Key actions" items={[{ label: "Activate", onSelect: () => setOpen(true) }]} />
      <Modal open={open} title="Activate?" onClose={() => setOpen(false)}><input id="field" /></Modal>
    </>
  );
}

describe("RowMenu + Modal focus", () => {
  it("returns focus to the menu trigger when a dialog opened from the menu closes", () => {
    act(() => root.render(<Harness />));
    const trigger = document.querySelector("button[aria-label='Key actions']") as HTMLButtonElement;
    act(() => trigger.click());
    const item = document.querySelector("[role=menuitem]") as HTMLButtonElement;
    act(() => item.click());
    expect(document.activeElement?.id).toBe("field");
    act(() => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })); });
    expect(document.querySelector("[role=dialog]")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});
