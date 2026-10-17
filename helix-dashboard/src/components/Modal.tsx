/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Button } from "./Button";
import { useT } from "../i18n/LocaleContext";

export interface ModalProps {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  width?: number;
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), '
  + 'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** The dialog's focusable elements, in document order. */
export function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
}

/**
 * Centered modal dialog with scrim. Esc + scrim-click close. Focus moves into the dialog when it opens (its first
 * field, else its heading), Tab and Shift+Tab stay inside it, and focus returns to whatever opened it on close.
 */
export function Modal({ open, title, onClose, children, footer, width = 520 }: ModalProps) {
  const dialogRef = React.useRef<HTMLDivElement>(null);
  const headingRef = React.useRef<HTMLHeadingElement>(null);
  const titleId = React.useId();
  const onCloseRef = React.useRef(onClose);
  onCloseRef.current = onClose;

  React.useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    if (dialog) {
      const body = dialog.querySelector<HTMLElement>(".hx-modal__body");
      const field = body ? focusables(body)[0] : undefined;
      (field ?? headingRef.current)?.focus();
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onCloseRef.current();
        return;
      }
      if (e.key !== "Tab" || !dialogRef.current) return;
      const items = focusables(dialogRef.current);
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      const inside = active instanceof Node && dialogRef.current.contains(active);
      if (e.shiftKey && (active === first || !inside || active === headingRef.current)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !inside)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (opener && opener.isConnected) opener.focus();
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className="hx-scrim-modal" onMouseDown={onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="hx-dialog"
        onMouseDown={(e) => e.stopPropagation()}
        // Each dialog picks its own width (an open-ended author-supplied number across dozens of call
        // sites, not a fixed set a class could enumerate) — carried as a custom property.
        style={{ "--modal-maxw": `${width}px` } as React.CSSProperties}
      >
        <header className="hx-modal__head">
          <h3 className="hx-modal__title" id={titleId} ref={headingRef} tabIndex={-1}>{title}</h3>
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
  /** Defaults to the localised "Delete". */
  confirmLabel?: string;
  /** Defaults to the localised "Cancel". */
  cancelLabel?: string;
  /** The confirm button's style: `danger` (default, destructive) or `primary` (a positive decision). */
  tone?: "danger" | "primary";
  onConfirm: () => void;
  onCancel: () => void;
}

/** A Modal preset for a confirmation: destructive by default (e.g. delete a connection), or `tone="primary"`. */
export function ConfirmDialog({ open, title, message, confirmLabel, cancelLabel, tone = "danger", onConfirm, onCancel }: ConfirmDialogProps) {
  const { t } = useT();
  return (
    <Modal
      open={open}
      title={title}
      onClose={onCancel}
      width={440}
      footer={
        <>
          <Button variant="ghost" onClick={onCancel}>{cancelLabel ?? t("common.cancel")}</Button>
          <Button variant={tone === "primary" ? "primary" : "danger"} onClick={onConfirm}>{confirmLabel ?? t("common.delete")}</Button>
        </>
      }
    >
      {message}
    </Modal>
  );
}
