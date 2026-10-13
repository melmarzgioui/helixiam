/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Toast, ToastTone } from "./Toast";

export type { ToastTone };

export interface ToastInput {
  tone: ToastTone;
  title: React.ReactNode;
  message?: React.ReactNode;
  /** Override the default auto-dismiss delay (ms) for a success/info toast. Ignored for "error" — it never auto-dismisses. */
  durationMs?: number;
}

interface ToastItem extends ToastInput {
  id: number;
}

interface ToastApi {
  show: (toast: ToastInput) => void;
}

interface PlacementApi {
  claimTop: () => void;
  releaseTop: () => void;
}

const ToastContext = React.createContext<ToastApi | null>(null);
const PlacementContext = React.createContext<PlacementApi | null>(null);

/** At most this many toasts show at once — older ones (beyond the cap) are dropped, not queued. */
const MAX_VISIBLE = 3;
const DEFAULT_AUTO_DISMISS_MS = 5000;

/**
 * ONE shared toast host for an app (mount once, near the root — see App.tsx / AccountApp.tsx). Every page calls
 * `useToast().show(...)` instead of keeping its own `note` state + `.hx-toasthost`, so two toasts from different
 * parts of the tree (e.g. an Application page and the client editor embedded in it) stack in the same place
 * instead of two independent fixed-position hosts painting over each other.
 */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = React.useState<ToastItem[]>([]);
  const nextId = React.useRef(1);
  const timers = React.useRef(new Map<number, ReturnType<typeof setTimeout>>());
  const [topClaims, setTopClaims] = React.useState(0);

  const dismiss = React.useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer) { clearTimeout(timer); timers.current.delete(id); }
    setItems((xs) => xs.filter((x) => x.id !== id));
  }, []);

  const show = React.useCallback((toast: ToastInput) => {
    const id = nextId.current++;
    setItems((xs) => {
      const next = [...xs, { ...toast, id }];
      // Keep only the most recent MAX_VISIBLE — newest stays, oldest beyond the cap drops off (not queued).
      return next.length > MAX_VISIBLE ? next.slice(next.length - MAX_VISIBLE) : next;
    });
    if (toast.tone !== "error") {
      const ms = toast.durationMs ?? DEFAULT_AUTO_DISMISS_MS;
      timers.current.set(id, setTimeout(() => dismiss(id), ms));
    }
  }, [dismiss]);

  React.useEffect(() => {
    const current = timers.current;
    return () => current.forEach((t) => clearTimeout(t));
  }, []);

  const toastApi = React.useMemo<ToastApi>(() => ({ show }), [show]);
  const placementApi = React.useMemo<PlacementApi>(() => ({
    claimTop: () => setTopClaims((n) => n + 1),
    releaseTop: () => setTopClaims((n) => Math.max(0, n - 1)),
  }), []);

  return (
    <ToastContext.Provider value={toastApi}>
      <PlacementContext.Provider value={placementApi}>
        {children}
        <div className={topClaims > 0 ? "hx-toasthost hx-toasthost--savebar" : "hx-toasthost"}>
          {items.map((it) => (
            <Toast key={it.id} tone={it.tone} title={it.title} message={it.message} onDismiss={() => dismiss(it.id)} />
          ))}
        </div>
      </PlacementContext.Provider>
    </ToastContext.Provider>
  );
}

/** Show a transient toast through the app's single shared host. Must be called under a `ToastProvider`. */
export function useToast(): ToastApi {
  const ctx = React.useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within a ToastProvider");
  return ctx;
}

/**
 * Declare (while `active`) that this page has its own sticky bottom action bar (`.hx-savebar`, e.g. the Email
 * provider form), so the shared toast host moves to the top of the page instead of its default bottom-right corner,
 * where it would otherwise sit over the bar. Several mounted callers can claim this at once (switching tabs, a
 * nested form) — the host stays at the top as long as ANY of them still wants it there.
 */
export function useAvoidBottomToast(active: boolean): void {
  const ctx = React.useContext(PlacementContext);
  React.useEffect(() => {
    if (!active || !ctx) return;
    ctx.claimTop();
    return () => ctx.releaseTop();
  }, [active, ctx]);
}
