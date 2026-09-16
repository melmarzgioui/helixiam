import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  /** Panel width (CSS length). Defaults to min(480px, 100vw); full-width on mobile via CSS. */
  width?: string;
}

/**
 * Right-side overlay panel. Reusable across tables — pass `open`/`onClose`/`title`/`children` (and an
 * optional `footer`). Portals to <body>, dims the page with a scrim, and closes on Escape, backdrop click,
 * or the × button. Locks body scroll while open and restores focus to the trigger on close.
 */
export function Drawer({ open, onClose, title, children, footer, width }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<Element | null>(null);

  useEffect(() => {
    if (!open) return;
    returnFocus.current = document.activeElement;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    panelRef.current?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      (returnFocus.current as HTMLElement | null)?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="hx-drawer-root">
      <div className="hx-drawer-scrim" onClick={onClose} />
      <div
        ref={panelRef}
        className="hx-drawer-panel"
        style={width ? { width } : undefined}
        role="dialog"
        aria-modal="true"
        aria-labelledby="hx-drawer-title"
        tabIndex={-1}
      >
        <div className="hx-drawer-head">
          <h2 id="hx-drawer-title" className="hx-drawer-title">{title}</h2>
          <button className="hx-drawer-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="hx-drawer-body">{children}</div>
        {footer ? <div className="hx-drawer-foot">{footer}</div> : null}
      </div>
    </div>,
    document.body,
  );
}
