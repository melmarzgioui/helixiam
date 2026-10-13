/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// @vitest-environment jsdom

import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ToastProvider, useToast, useAvoidBottomToast } from "./ToastProvider";

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
  vi.useRealTimers();
});

function host(): HTMLElement {
  return container.querySelector(".hx-toasthost") as HTMLElement;
}

/** A caller that exposes its `show`/`useAvoidBottomToast` via a ref-like callback, like a real page would. */
function Caller({ onReady, avoidBottom }: { onReady: (show: ReturnType<typeof useToast>["show"]) => void; avoidBottom?: boolean }) {
  const { show } = useToast();
  useAvoidBottomToast(!!avoidBottom);
  onReady(show);
  return null;
}

describe("ToastProvider / useToast", () => {
  it("renders exactly one shared host for the whole subtree", () => {
    act(() => root.render(
      <ToastProvider>
        <Caller onReady={() => undefined} />
        <Caller onReady={() => undefined} />
      </ToastProvider>,
    ));
    expect(container.querySelectorAll(".hx-toasthost").length).toBe(1);
  });

  it("two independent callers (e.g. a parent page and its embedded child) both land in the SAME host — neither hides the other", () => {
    let showParent!: ReturnType<typeof useToast>["show"];
    let showChild!: ReturnType<typeof useToast>["show"];
    act(() => root.render(
      <ToastProvider>
        <Caller onReady={(s) => { showParent = s; }} />
        <Caller onReady={(s) => { showChild = s; }} />
      </ToastProvider>,
    ));
    act(() => showParent({ tone: "success", title: "OIDC client attached" }));
    act(() => showChild({ tone: "error", title: "Client kon niet worden opgeslagen" }));

    expect(container.querySelectorAll(".hx-toasthost").length).toBe(1);
    const toasts = host().querySelectorAll(".hx-toast");
    expect(toasts.length).toBe(2);
    expect(host().textContent).toContain("OIDC client attached");
    expect(host().textContent).toContain("Client kon niet worden opgeslagen");
  });

  it("stacks newest closest to the end of the DOM (closest to the corner) and caps at 3 visible", () => {
    let show!: ReturnType<typeof useToast>["show"];
    act(() => root.render(<ToastProvider><Caller onReady={(s) => { show = s; }} /></ToastProvider>));
    act(() => { show({ tone: "info", title: "one" }); show({ tone: "info", title: "two" });
      show({ tone: "info", title: "three" }); show({ tone: "info", title: "four" }); });
    const titles = Array.from(host().querySelectorAll(".hx-toast__title")).map((n) => n.textContent);
    expect(titles).toEqual(["two", "three", "four"]); // "one" dropped — oldest beyond the cap
  });

  it("an error toast never auto-dismisses", () => {
    vi.useFakeTimers();
    let show!: ReturnType<typeof useToast>["show"];
    act(() => root.render(<ToastProvider><Caller onReady={(s) => { show = s; }} /></ToastProvider>));
    act(() => show({ tone: "error", title: "Could not save client" }));
    act(() => { vi.advanceTimersByTime(60_000); });
    expect(host().querySelectorAll(".hx-toast").length).toBe(1);
  });

  it("a success toast auto-dismisses after a few seconds", () => {
    vi.useFakeTimers();
    let show!: ReturnType<typeof useToast>["show"];
    act(() => root.render(<ToastProvider><Caller onReady={(s) => { show = s; }} /></ToastProvider>));
    act(() => show({ tone: "success", title: "Client saved" }));
    expect(host().querySelectorAll(".hx-toast").length).toBe(1);
    act(() => { vi.advanceTimersByTime(10_000); });
    expect(host().querySelectorAll(".hx-toast").length).toBe(0);
  });

  it("dismissing a toast (the close button) removes just that one", () => {
    let show!: ReturnType<typeof useToast>["show"];
    act(() => root.render(<ToastProvider><Caller onReady={(s) => { show = s; }} /></ToastProvider>));
    act(() => { show({ tone: "error", title: "first" }); show({ tone: "error", title: "second" }); });
    const closeButtons = host().querySelectorAll<HTMLButtonElement>(".hx-toast__x");
    expect(closeButtons.length).toBe(2);
    act(() => closeButtons[0].click());
    expect(Array.from(host().querySelectorAll(".hx-toast__title")).map((n) => n.textContent)).toEqual(["second"]);
  });

  it("error toasts carry role=alert/aria-live=assertive; success carries status/polite", () => {
    let show!: ReturnType<typeof useToast>["show"];
    act(() => root.render(<ToastProvider><Caller onReady={(s) => { show = s; }} /></ToastProvider>));
    act(() => { show({ tone: "error", title: "bad" }); show({ tone: "success", title: "good" }); });
    const alert = host().querySelector('[role="alert"]');
    expect(alert?.getAttribute("aria-live")).toBe("assertive");
    const status = host().querySelector('[role="status"]');
    expect(status?.getAttribute("aria-live")).toBe("polite");
  });

  it("useAvoidBottomToast moves the host to the top (savebar) placement while any caller wants it", () => {
    let setA!: (v: boolean) => void;
    let setB!: (v: boolean) => void;
    function Toggle({ onA, onB }: { onA: (fn: (v: boolean) => void) => void; onB: (fn: (v: boolean) => void) => void }) {
      const [a, sa] = React.useState(false);
      const [b, sb] = React.useState(false);
      onA(sa); onB(sb);
      return (
        <ToastProvider>
          <Caller onReady={() => undefined} avoidBottom={a} />
          <Caller onReady={() => undefined} avoidBottom={b} />
        </ToastProvider>
      );
    }
    act(() => root.render(<Toggle onA={(fn) => { setA = fn; }} onB={(fn) => { setB = fn; }} />));
    expect(host().className).not.toContain("hx-toasthost--savebar");

    act(() => setA(true));
    expect(host().className).toContain("hx-toasthost--savebar");

    act(() => setB(true));
    act(() => setA(false)); // one claimant released, the other still wants it
    expect(host().className).toContain("hx-toasthost--savebar");

    act(() => setB(false));
    expect(host().className).not.toContain("hx-toasthost--savebar");
  });

  it("useToast throws outside a ToastProvider", () => {
    const Bare = () => { useToast(); return null; };
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(() => act(() => root.render(<Bare />))).toThrow(/ToastProvider/);
    spy.mockRestore();
  });
});
