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
      <button ref={btnRef} type="button" aria-label={ariaLabel} aria-haspopup="menu" aria-expanded={open} onClick={toggle}
        style={{ width: 32, height: 32, border: "1px solid transparent", borderRadius: "var(--r-sm)", background: open ? "var(--surface)" : "transparent", color: "var(--fg-muted)", cursor: "pointer", display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="12" cy="5" r="1.6" /><circle cx="12" cy="12" r="1.6" /><circle cx="12" cy="19" r="1.6" /></svg>
      </button>
      {open && pos && createPortal(
        <div ref={menuRef} role="menu" style={{ position: "fixed", top: pos.top, right: pos.right, zIndex: 90, minWidth: 190, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: "var(--r-sm)", boxShadow: "var(--shadow-lg)", padding: ".3rem", textAlign: "left" }}>
          {items.map((it) => (
            <button key={it.label} role="menuitem" onClick={() => { setOpen(false); it.onSelect(); }}
              style={{ display: "block", width: "100%", textAlign: "left", padding: ".5rem .6rem", border: "none", borderRadius: "calc(var(--r-sm) - 4px)", background: "transparent", color: it.danger ? "var(--danger-fg)" : "var(--fg)", font: "500 .9rem var(--font)", cursor: "pointer" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >{it.label}</button>
          ))}
        </div>,
        document.body
      )}
    </>
  );
}
