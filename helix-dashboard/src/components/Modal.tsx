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
        // Each dialog picks its own width (an open-ended author-supplied number across dozens of call
        // sites, not a fixed set a class could enumerate) — carried as a custom property.
        style={{ "--modal-maxw": `${width}px` } as React.CSSProperties}
      >
        <header className="hx-modal__head">
          <h3 className="hx-modal__title">{title}</h3>
          <button type="button" aria-label="Close" className="hx-ghosticon hx-modal__close" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </button>
        </header>
        <div className="hx-modal__body">{children}</div>
        {footer && (
          <footer className="hx-modal__foot">
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
