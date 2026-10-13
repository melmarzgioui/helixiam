/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// @vitest-environment jsdom

import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { useFocusInvalid } from "./useFocusInvalid";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  // jsdom doesn't implement layout, so scrollIntoView isn't provided — stub it so we can assert the call.
  Element.prototype.scrollIntoView = vi.fn();
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function Form({ invalidKey, getTrigger }: { invalidKey: "a" | "b" | "none"; getTrigger: (fn: () => void) => void }) {
  const trigger = useFocusInvalid();
  getTrigger(trigger);
  return (
    <div>
      <input aria-invalid={invalidKey === "a" ? "true" : undefined} data-testid="a" />
      <input aria-invalid={invalidKey === "b" ? "true" : undefined} data-testid="b" />
    </div>
  );
}

function ScopedForm({ getTrigger }: { getTrigger: (fn: () => void, root: React.RefObject<HTMLDivElement | null>) => void }) {
  const rootRef = React.useRef<HTMLDivElement>(null);
  const trigger = useFocusInvalid(rootRef);
  getTrigger(trigger, rootRef);
  return (
    <div>
      <input aria-invalid="true" data-testid="outside" />
      <div ref={rootRef}>
        <input data-testid="inside" />
      </div>
    </div>
  );
}

describe("useFocusInvalid", () => {
  it("does nothing until triggered", () => {
    let trigger!: () => void;
    act(() => root.render(<Form invalidKey="a" getTrigger={(fn) => { trigger = fn; }} />));
    void trigger;
    expect(document.activeElement).not.toBe(container.querySelector('[data-testid="a"]'));
  });

  it("focuses and scrolls the first [aria-invalid=true] field once triggered", () => {
    let trigger!: () => void;
    act(() => root.render(<Form invalidKey="b" getTrigger={(fn) => { trigger = fn; }} />));
    act(() => trigger());
    const b = container.querySelector('[data-testid="b"]') as HTMLElement;
    expect(document.activeElement).toBe(b);
    expect(b.scrollIntoView).toHaveBeenCalledWith(expect.objectContaining({ block: "center" }));
  });

  it("is a no-op when nothing is invalid", () => {
    let trigger!: () => void;
    const previouslyFocused = document.activeElement;
    act(() => root.render(<Form invalidKey="none" getTrigger={(fn) => { trigger = fn; }} />));
    act(() => trigger());
    expect(document.activeElement).toBe(previouslyFocused);
  });

  it("re-triggering after a field becomes invalid (e.g. a tab switch rendered it) focuses it", () => {
    let trigger!: () => void;
    const { rerender } = { rerender: (el: React.ReactElement) => act(() => root.render(el)) };
    rerender(<Form invalidKey="none" getTrigger={(fn) => { trigger = fn; }} />);
    act(() => trigger()); // nothing invalid yet — no-op
    rerender(<Form invalidKey="a" getTrigger={(fn) => { trigger = fn; }} />); // the tab switch reveals the field
    act(() => trigger());
    expect(document.activeElement).toBe(container.querySelector('[data-testid="a"]'));
  });

  it("scopes to the given root ref, ignoring an invalid field outside it", () => {
    let trigger!: () => void;
    act(() => root.render(<ScopedForm getTrigger={(fn) => { trigger = fn; }} />));
    const outsideBefore = document.activeElement;
    act(() => trigger());
    // The only [aria-invalid=true] field is outside the scoped root, so nothing inside gets focused.
    expect(document.activeElement).toBe(outsideBefore);
  });
});
