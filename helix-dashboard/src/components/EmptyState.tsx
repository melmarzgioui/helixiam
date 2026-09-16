import React from "react";

export interface EmptyStateProps {
  title: React.ReactNode;
  message?: React.ReactNode;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}

/** Empty placeholder — e.g. "No identity providers yet". Class-based (components.css). */
export function EmptyState({ title, message, icon, action }: EmptyStateProps) {
  return (
    <div className="hx-empty">
      <span className="hx-empty__icon">
        {icon ?? (
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <rect x="3" y="5" width="18" height="14" rx="2" stroke="currentColor" strokeWidth="1.5" />
            <path d="M3 9h18M8 14h5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        )}
      </span>
      <h3 className="hx-empty__title">{title}</h3>
      {message && <p className="hx-empty__msg">{message}</p>}
      {action && <div className="hx-empty__action">{action}</div>}
    </div>
  );
}
