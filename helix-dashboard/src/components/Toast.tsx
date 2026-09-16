import React from "react";

export type ToastTone = "success" | "error" | "info";

export interface ToastProps {
  tone?: ToastTone;
  title: React.ReactNode;
  message?: React.ReactNode;
  onDismiss?: () => void;
}

const glyph: Record<ToastTone, React.ReactNode> = {
  success: <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />,
  error: <path d="M12 8v5M12 16.5v.01M12 3l9 16H3z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
  info: <path d="M12 11v6M12 7.5v.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />,
};

/** Single toast notification. Compose a stack in your app's toast region (ToastHost / .hx-toasthost). Class-based. */
export function Toast({ tone = "info", title, message, onDismiss }: ToastProps) {
  return (
    <div role="status" className={`hx-toast hx-toast--${tone}`}>
      <svg className="hx-toast__icon" width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        {glyph[tone]}
      </svg>
      <div className="hx-toast__body">
        <div className="hx-toast__title">{title}</div>
        {message && <div className="hx-toast__msg">{message}</div>}
      </div>
      {onDismiss && (
        <button type="button" className="hx-toast__x" aria-label="Dismiss" onClick={onDismiss}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </button>
      )}
    </div>
  );
}
