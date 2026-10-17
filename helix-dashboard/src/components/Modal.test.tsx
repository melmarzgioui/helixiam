/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// @vitest-environment jsdom

import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
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

function tab(shift = false) {
  const e = new KeyboardEvent("keydown", { key: "Tab", shiftKey: shift, bubbles: true, cancelable: true });
  (document.activeElement ?? document.body).dispatchEvent(e);
  return e;
}

function Harness({ withFields = true, onClose = () => undefined }: { withFields?: boolean; onClose?: () => void }) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <button id="opener" onClick={() => setOpen(true)}>open</button>
      <Modal open={open} title="Dialog title" onClose={() => { setOpen(false); onClose(); }}
        footer={<button id="ok">OK</button>}>
        {withFields ? <><input id="first" /><input id="second" /></> : <p>Text only</p>}
      </Modal>
    </>
  );
}

const byId = (id: string) => document.getElementById(id) as HTMLElement;

describe("Modal focus management", () => {
  it("moves focus to the first field when it opens", () => {
    act(() => root.render(<Harness />));
    byId("opener").focus();
    act(() => byId("opener").click());
    expect(document.activeElement).toBe(byId("first"));
  });

  it("focuses the heading when the dialog has no field", () => {
    act(() => root.render(<Harness withFields={false} />));
    act(() => byId("opener").click());
    expect(document.activeElement?.textContent).toBe("Dialog title");
  });

  it("traps Tab and Shift+Tab inside the dialog", () => {
    act(() => root.render(<Harness />));
    act(() => byId("opener").click());
    const dialog = document.querySelector("[role=dialog]") as HTMLElement;
    // Last focusable → Tab wraps to the first (the close button comes first in the dialog).
    byId("ok").focus();
    const forward = tab();
    expect(forward.defaultPrevented).toBe(true);
    expect(dialog.contains(document.activeElement)).toBe(true);
    const first = dialog.querySelector("button, input") as HTMLElement;
    expect(document.activeElement).toBe(first);
    // First → Shift+Tab wraps to the last.
    const back = tab(true);
    expect(back.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(byId("ok"));
    // In the middle Tab is left to the browser.
    byId("first").focus();
    expect(tab().defaultPrevented).toBe(false);
  });

  it("closes on Escape and gives focus back to the opener", () => {
    const onClose = vi.fn();
    act(() => root.render(<Harness onClose={onClose} />));
    byId("opener").focus();
    act(() => byId("opener").click());
    expect(document.activeElement).toBe(byId("first"));
    act(() => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })); });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(document.querySelector("[role=dialog]")).toBeNull();
    expect(document.activeElement).toBe(byId("opener"));
  });
});
