/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { createPortal } from "react-dom";

/** A single action in a table row's overflow menu. Omit items from the array to hide them. */
export interface RowMenuItem {
  label: string;
  onSelect: () => void;
  /** Renders the item in the destructive (red) treatment. */
  danger?: boolean;
}

/**
 * The unified table-row action control: a kebab (⋮) trigger that opens a portalled overflow menu.
 * Every table in the console uses this so row actions look and behave identically. The panel is
 * portalled to <body> with fixed positioning so it escapes card overflow / stacking contexts, and
 * closes on outside-click, Escape, scroll and resize.
 */
export function RowMenu({ items, ariaLabel = "Row actions" }: { items: RowMenuItem[]; ariaLabel?: string }) {
  const [open, setOpen] = React.useState(false);
  const [pos, setPos] = React.useState<{ top: number; right: number } | null>(null);
  const btnRef = React.useRef<HTMLButtonElement>(null);
  const menuRef = React.useRef<HTMLDivElement>(null);

  const place = () => {
    const r = btnRef.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 4, right: window.innerWidth - r.right });
  };
  const toggle = () => { if (!open) place(); setOpen((v) => !v); };

  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { const t = e.target as Node; if (!btnRef.current?.contains(t) && !menuRef.current?.contains(t)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    const onScroll = () => setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [open]);

  return (
    <>
      <button ref={btnRef} type="button" aria-label={ariaLabel} aria-haspopup="menu" aria-expanded={open} onClick={toggle} className="hx-kebabbtn">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="12" cy="5" r="1.6" /><circle cx="12" cy="12" r="1.6" /><circle cx="12" cy="19" r="1.6" /></svg>
      </button>
      {open && pos && createPortal(
        // The menu's screen position is computed from the trigger's own bounding rect — a value CSS
        // cannot express — so it is carried as custom properties, never as literal style props.
        <div ref={menuRef} role="menu" className="hx-portalmenu"
          style={{ "--mx-top": `${pos.top}px`, "--mx-right": `${pos.right}px` } as React.CSSProperties}>
          {items.map((it) => (
            <button key={it.label} role="menuitem" onClick={() => { setOpen(false); it.onSelect(); }}
              className={`hx-portalmenu-item${it.danger ? " hx-portalmenu-item--danger" : ""}`}
            >{it.label}</button>
          ))}
        </div>,
        document.body
      )}
    </>
  );
}
