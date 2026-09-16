/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Button } from "./Button";

export interface ModalProps {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  width?: number;
}

/** Centered modal dialog with scrim. Esc + scrim-click close. */
export function Modal({ open, title, onClose, children, footer, width = 520 }: ModalProps) {
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="hx-scrim-modal" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        className="hx-dialog"
        onMouseDown={(e) => e.stopPropagation()}
        style={{ maxWidth: width }}
      >
        <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem", padding: "1.1rem 1.3rem", borderBottom: "1px solid var(--border)" }}>
          <h3 style={{ margin: 0, fontSize: "1.1rem", color: "var(--fg)" }}>{title}</h3>
          <button type="button" aria-label="Close" className="hx-ghosticon" onClick={onClose} style={{ width: 32, height: 32 }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </button>
        </header>
        <div style={{ padding: "1.3rem", color: "var(--fg-muted)", overflowY: "auto", flex: 1 }}>{children}</div>
        {footer && (
          <footer style={{ display: "flex", justifyContent: "flex-end", gap: ".6rem", padding: "1rem 1.3rem", borderTop: "1px solid var(--border)", flexShrink: 0 }}>
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}

export interface ConfirmDialogProps {
  open: boolean;
  title: React.ReactNode;
  message: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/** A Modal preset for destructive confirmation (e.g. delete a connection). */
export function ConfirmDialog({ open, title, message, confirmLabel = "Delete", cancelLabel = "Cancel", onConfirm, onCancel }: ConfirmDialogProps) {
  return (
    <Modal
      open={open}
      title={title}
      onClose={onCancel}
      width={440}
      footer={
        <>
          <Button variant="ghost" onClick={onCancel}>{cancelLabel}</Button>
          <Button variant="danger" onClick={onConfirm}>{confirmLabel}</Button>
        </>
      }
    >
      {message}
    </Modal>
  );
}
