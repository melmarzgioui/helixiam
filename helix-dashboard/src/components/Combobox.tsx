import React from "react";
import { createPortal } from "react-dom";

export interface ComboOption {
  value: string;
  label: string;
  /** Optional secondary line shown under the label (e.g. the email / client id). */
  description?: string;
  /** Optional group label — used by {@link MultiCombobox} to section the panel (e.g. "Realm roles"). */
  group?: string;
}

export interface ComboboxProps {
  /** The committed value (an option's `value`, or a free-typed custom string). */
  value: string;
  onChange: (value: string) => void;
  options: ComboOption[];
  placeholder?: string;
  disabled?: boolean;
  /** When true, text that matches no option is still accepted as the value (e.g. an external email). */
  allowCustom?: boolean;
  /** Shown while the option list is still loading. */
  loading?: boolean;
  /** Message when the filter matches nothing (and custom entry is off). */
  emptyText?: string;
  id?: string;
  "aria-label"?: string;
}

/** Pure filter: case-insensitive substring match on an option's label, value, or description. */
export function filterComboOptions(options: ComboOption[], query: string): ComboOption[] {
  const q = query.trim().toLowerCase();
  if (!q) return options;
  return options.filter(
    (o) =>
      o.label.toLowerCase().includes(q) ||
      o.value.toLowerCase().includes(q) ||
      (o.description ?? "").toLowerCase().includes(q),
  );
}

/** The text to show for a committed value: the matching option's label, or the raw value if custom. */
export function comboDisplayLabel(value: string, options: ComboOption[]): string {
  if (!value) return "";
  return options.find((o) => o.value === value)?.label ?? value;
}

/**
 * Searchable single-select — a text input that filters a portalled option panel as you type. Reusable
 * across the console (owner pickers, client pickers, …). Reuses the {@code Select} panel/option styles.
 * Keyboard: ↑/↓ move, Enter picks the highlight (or, with {@code allowCustom}, commits the typed text),
 * Esc closes. Closing without a pick reverts to the current value; blurring with typed text commits it
 * when {@code allowCustom}.
 */
export function Combobox({
  value,
  onChange,
  options,
  placeholder = "Search…",
  disabled,
  allowCustom,
  loading,
  emptyText = "No matches",
  id,
  ...aria
}: ComboboxProps) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState(""); // live search text while open
  const [dirty, setDirty] = React.useState(false); // has the user typed since opening?
  const [active, setActive] = React.useState(0);
  const [pos, setPos] = React.useState<{ top: number; left: number; width: number } | null>(null);
  const rootRef = React.useRef<HTMLDivElement>(null);
  const listRef = React.useRef<HTMLUListElement>(null);

  const filtered = open ? filterComboOptions(options, query) : options;
  const display = open ? query : comboDisplayLabel(value, options);

  const place = () => {
    const r = rootRef.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 6, left: r.left, width: r.width });
  };

  const openMenu = () => {
    if (disabled) return;
    setQuery("");
    setDirty(false);
    setActive(0);
    place();
    setOpen(true);
  };

  const commit = (next: string) => {
    onChange(next);
    setOpen(false);
    setDirty(false);
  };

  const close = () => {
    setOpen(false);
    setDirty(false);
  };

  // Commit the typed text (custom) or revert, then close — used on blur / outside click.
  const finish = () => {
    if (dirty && allowCustom && query.trim()) commit(query.trim());
    else close();
  };

  React.useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!rootRef.current?.contains(t) && !listRef.current?.contains(t)) finish();
    };
    const onScroll = () => close();
    document.addEventListener("mousedown", onDocClick);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, dirty, query, allowCustom]);

  React.useEffect(() => {
    if (!open || !listRef.current) return;
    (listRef.current.children[active] as HTMLElement | undefined)?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  const onKey = (e: React.KeyboardEvent) => {
    if (disabled) return;
    if (!open && (e.key === "ArrowDown" || e.key === "Enter")) {
      e.preventDefault();
      openMenu();
      return;
    }
    if (!open) return;
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setActive((i) => Math.min(i + 1, Math.max(filtered.length - 1, 0)));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(i - 1, 0));
        break;
      case "Enter":
        e.preventDefault();
        if (filtered[active]) commit(filtered[active].value);
        else if (allowCustom && query.trim()) commit(query.trim());
        break;
      case "Escape":
        e.preventDefault();
        close();
        break;
      case "Tab":
        finish();
        break;
    }
  };

  return (
    <div ref={rootRef} className="hx-combo">
      <input
        id={id}
        type="text"
        className="hx-input hx-combo__input"
        role="combobox"
        aria-expanded={open}
        aria-autocomplete="list"
        aria-label={aria["aria-label"]}
        autoComplete="off"
        disabled={disabled}
        placeholder={placeholder}
        value={display}
        onFocus={openMenu}
        onClick={() => !open && openMenu()}
        onChange={(e) => {
          setQuery(e.target.value);
          setDirty(true);
          setActive(0);
          if (!open) {
            place();
            setOpen(true);
          }
        }}
        onKeyDown={onKey}
      />
      <svg className="hx-combo__chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>

      {open && pos && createPortal(
        <ul ref={listRef} role="listbox" className="hx-select-panel"
          style={{ position: "fixed", top: pos.top, left: pos.left, width: pos.width, right: "auto", zIndex: 95 }}>
          {loading ? (
            <li className="hx-option hx-combo__msg">Loading…</li>
          ) : filtered.length === 0 ? (
            <li className="hx-option hx-combo__msg">
              {allowCustom && query.trim() ? `Use “${query.trim()}”` : emptyText}
            </li>
          ) : (
            filtered.map((o, i) => (
              <li
                key={o.value}
                role="option"
                aria-selected={o.value === value}
                className={`hx-option${i === active ? " hx-option--active" : ""}`}
                onMouseEnter={() => setActive(i)}
                // preventDefault keeps focus on the input so its blur doesn't fire before the click.
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => commit(o.value)}
              >
                <span className="hx-combo__opt">
                  <span className="hx-combo__opt-label">{o.label}</span>
                  {o.description && <span className="hx-combo__opt-desc">{o.description}</span>}
                </span>
              </li>
            ))
          )}
        </ul>,
        document.body,
      )}
    </div>
  );
}
