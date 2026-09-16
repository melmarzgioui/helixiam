/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { createPortal } from "react-dom";
import { ComboOption, filterComboOptions, comboDisplayLabel } from "./Combobox";

export interface MultiComboboxProps {
  /** The selected option values. */
  values: string[];
  onChange: (values: string[]) => void;
  /** Options may carry an optional `group` label — rendered as a section header in the panel. */
  options: ComboOption[];
  placeholder?: string;
  disabled?: boolean;
  loading?: boolean;
  emptyText?: string;
  id?: string;
  "aria-label"?: string;
}

/** Add `v` if absent, remove it if present. */
export function toggleValue(values: string[], v: string): string[] {
  return values.includes(v) ? values.filter((x) => x !== v) : [...values, v];
}

export interface ComboGroup {
  group: string;
  options: ComboOption[];
}

/** Bucket options by their `group` label, preserving first-seen group order; ungrouped ("") goes last. */
export function groupComboOptions(options: ComboOption[]): ComboGroup[] {
  const order: string[] = [];
  const byGroup = new Map<string, ComboOption[]>();
  for (const o of options) {
    const g = o.group ?? "";
    if (!byGroup.has(g)) {
      byGroup.set(g, []);
      if (g) order.push(g);
    }
    byGroup.get(g)!.push(o);
  }
  const groups = order.map((g) => ({ group: g, options: byGroup.get(g)! }));
  if (byGroup.has("")) groups.push({ group: "", options: byGroup.get("")! });
  return groups;
}

/**
 * Searchable MULTI-select — chips for the chosen values plus a filter input that opens a grouped, portalled
 * option panel. Reusable across the console (roles pickers, scope pickers, …). Selection-only (options must
 * exist); options may carry a `group` label to section the panel (e.g. "Realm roles" vs "Client: X"). Reuses
 * the {@link Combobox} option/panel styles. Keyboard: type to filter, Backspace removes the last chip, Esc closes.
 */
export function MultiCombobox({
  values,
  onChange,
  options,
  placeholder = "Search…",
  disabled,
  loading,
  emptyText = "No matches",
  id,
  ...aria
}: MultiComboboxProps) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [pos, setPos] = React.useState<{ top: number; left: number; width: number } | null>(null);
  const rootRef = React.useRef<HTMLDivElement>(null);
  const listRef = React.useRef<HTMLUListElement>(null);
  const inputRef = React.useRef<HTMLInputElement>(null);

  const groups = groupComboOptions(filterComboOptions(options, query));
  const visibleCount = groups.reduce((n, g) => n + g.options.length, 0);

  const place = () => {
    const r = rootRef.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 6, left: r.left, width: r.width });
  };
  const openMenu = () => {
    if (disabled) return;
    place();
    setOpen(true);
  };
  const toggle = (v: string) => {
    onChange(toggleValue(values, v));
    setQuery("");
    inputRef.current?.focus();
  };

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

  const onKey = (e: React.KeyboardEvent) => {
    if (disabled) return;
    if (e.key === "Escape") { setOpen(false); return; }
    if (e.key === "Backspace" && !query && values.length) {
      onChange(values.slice(0, -1));
      return;
    }
    if ((e.key === "ArrowDown" || e.key === "Enter") && !open) { e.preventDefault(); openMenu(); }
  };

  return (
    <div ref={rootRef} className="hx-combo hx-multicombo">
      <div className={`hx-input hx-multicombo__control${open ? " hx-multicombo__control--open" : ""}`}
        onClick={() => { if (!disabled) { inputRef.current?.focus(); openMenu(); } }}>
        {values.map((v) => (
          <span key={v} className="hx-chip hx-multicombo__chip">
            {comboDisplayLabel(v, options)}
            <button type="button" className="hx-multicombo__chipx" aria-label={`Remove ${v}`}
              onMouseDown={(e) => e.preventDefault()} onClick={(e) => { e.stopPropagation(); toggle(v); }}>×</button>
          </span>
        ))}
        <input
          ref={inputRef}
          id={id}
          type="text"
          className="hx-multicombo__input"
          role="combobox"
          aria-expanded={open}
          aria-autocomplete="list"
          aria-label={aria["aria-label"]}
          autoComplete="off"
          disabled={disabled}
          placeholder={values.length ? "" : placeholder}
          value={query}
          onFocus={openMenu}
          onChange={(e) => { setQuery(e.target.value); if (!open) { place(); setOpen(true); } }}
          onKeyDown={onKey}
        />
      </div>
      <svg className="hx-combo__chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>

      {open && pos && createPortal(
        <ul ref={listRef} role="listbox" aria-multiselectable="true" className="hx-select-panel"
          style={{ position: "fixed", top: pos.top, left: pos.left, width: pos.width, right: "auto", zIndex: 95 }}>
          {loading ? (
            <li className="hx-option hx-combo__msg">Loading…</li>
          ) : visibleCount === 0 ? (
            <li className="hx-option hx-combo__msg">{emptyText}</li>
          ) : (
            groups.map((g) => (
              <React.Fragment key={g.group || "__ungrouped"}>
                {g.group && <li className="hx-multicombo__grouphead" aria-hidden="true">{g.group}</li>}
                {g.options.map((o) => {
                  const checked = values.includes(o.value);
                  return (
                    <li
                      key={o.value}
                      role="option"
                      aria-selected={checked}
                      className={`hx-option hx-multicombo__opt${checked ? " hx-multicombo__opt--on" : ""}`}
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => toggle(o.value)}
                    >
                      <span className={`hx-multicombo__check${checked ? " hx-multicombo__check--on" : ""}`} aria-hidden="true">
                        {checked ? "✓" : ""}
                      </span>
                      <span className="hx-combo__opt">
                        <span className="hx-combo__opt-label">{o.label}</span>
                        {o.description && <span className="hx-combo__opt-desc">{o.description}</span>}
                      </span>
                    </li>
                  );
                })}
              </React.Fragment>
            ))
          )}
        </ul>,
        document.body,
      )}
    </div>
  );
}
