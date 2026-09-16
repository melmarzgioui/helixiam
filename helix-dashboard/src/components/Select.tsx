/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { createPortal } from "react-dom";

export interface SelectOption {
  value: string;
  label: string;
  /** Optional secondary line shown under the label (e.g. a koppelvlak hint). */
  description?: string;
}

export interface SelectProps {
  options: SelectOption[];
  value?: string;
  defaultValue?: string;
  onChange?: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  /** Accessible name when the field has no visible <label>. */
  "aria-label"?: string;
  id?: string;
}

/**
 * Branded dropdown (listbox) — replaces the native <select> so the trigger and the
 * option panel both follow BRANDBOOK_KUBEDNA_V2. Keyboard + click-outside supported.
 */
export function Select({
  options,
  value,
  defaultValue,
  onChange,
  placeholder = "Select…",
  disabled,
  id,
  ...aria
}: SelectProps) {
  const isControlled = value !== undefined;
  const [internal, setInternal] = React.useState<string | undefined>(defaultValue);
  const selected = isControlled ? value : internal;

  const [open, setOpen] = React.useState(false);
  const [active, setActive] = React.useState(0); // keyboard-highlighted index
  // Panel is portalled to <body> with fixed positioning so it escapes card overflow:hidden / stacking.
  const [pos, setPos] = React.useState<{ top: number; left: number; width: number } | null>(null);
  const rootRef = React.useRef<HTMLDivElement>(null);
  const listRef = React.useRef<HTMLUListElement>(null);

  const selectedOption = options.find((o) => o.value === selected);
  const selectedIndex = options.findIndex((o) => o.value === selected);

  const place = () => {
    const r = rootRef.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 6, left: r.left, width: r.width });
  };

  const commit = (next: string) => {
    if (!isControlled) setInternal(next);
    onChange?.(next);
    setOpen(false);
  };

  const openMenu = () => {
    if (disabled) return;
    setActive(selectedIndex >= 0 ? selectedIndex : 0);
    place();
    setOpen(true);
  };

  // Close on outside click / Escape, and on scroll/resize (the fixed position would otherwise go stale).
  React.useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!rootRef.current?.contains(t) && !listRef.current?.contains(t)) setOpen(false);
    };
    const onScroll = () => setOpen(false);
    document.addEventListener("mousedown", onDocClick);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [open]);

  // Keep the highlighted option scrolled into view.
  React.useEffect(() => {
    if (!open || !listRef.current) return;
    const el = listRef.current.children[active] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  const onTriggerKey = (e: React.KeyboardEvent) => {
    if (disabled) return;
    if (!open) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openMenu();
      }
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setActive((i) => Math.min(i + 1, options.length - 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(i - 1, 0));
        break;
      case "Home":
        e.preventDefault();
        setActive(0);
        break;
      case "End":
        e.preventDefault();
        setActive(options.length - 1);
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        if (options[active]) commit(options[active].value);
        break;
      case "Escape":
        e.preventDefault();
        setOpen(false);
        break;
      case "Tab":
        setOpen(false);
        break;
    }
  };

  return (
    <div ref={rootRef} style={{ position: "relative" }}>
      <button
        type="button"
        id={id}
        className="hx-select-trigger"
        style={{ color: selectedOption ? "var(--fg)" : "var(--fg-faint)" }}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={aria["aria-label"]}
        onClick={() => (open ? setOpen(false) : openMenu())}
        onKeyDown={onTriggerKey}
      >
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {selectedOption ? selectedOption.label : placeholder}
        </span>
        <Chevron />
      </button>

      {open && pos && createPortal(
        <ul ref={listRef} role="listbox" className="hx-select-panel"
          style={{ position: "fixed", top: pos.top, left: pos.left, width: pos.width, right: "auto", zIndex: 95 }}>
          {options.map((o, i) => {
            const isSelected = o.value === selected;
            const isActive = i === active;
            return (
              <li
                key={o.value}
                role="option"
                aria-selected={isSelected}
                className={`hx-option${isActive ? " hx-option--active" : ""}`}
                onMouseEnter={() => setActive(i)}
                // preventDefault stops a wrapping <label> (e.g. FormField) from re-dispatching
                // the click to the trigger button and instantly reopening the panel.
                onClick={(e) => {
                  e.preventDefault();
                  commit(o.value);
                }}
              >
                <Check visible={isSelected} />
                <span style={{ display: "block" }}>
                  <span style={{ display: "block", fontWeight: isSelected ? 600 : 400 }}>{o.label}</span>
                  {o.description && (
                    <span style={{ display: "block", fontSize: ".8rem", color: "var(--fg-faint)" }}>
                      {o.description}
                    </span>
                  )}
                </span>
              </li>
            );
          })}
        </ul>,
        document.body
      )}
    </div>
  );
}

function Chevron() {
  return (
    <svg className="hx-select-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Check({ visible }: { visible: boolean }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      style={{ flexShrink: 0, marginTop: 3, color: "var(--accent)", opacity: visible ? 1 : 0 }}
    >
      <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
