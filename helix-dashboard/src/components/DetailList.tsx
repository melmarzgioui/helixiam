import React from "react";

/**
 * DetailList — a reusable label/value "definition list" for drawers and detail panels.
 *
 * It fixes two recurring readability problems:
 *  1. Labels and their values blur together — here the label sits in its own faint,
 *     uppercase left column, clearly separated from the value on the right (stacks on mobile).
 *  2. Composite values (a relative time next to a raw timestamp, a name next to a UUID) run
 *     into one line — here each value has an optional muted `sub` line and a monospace `mono`
 *     line, so "in 14 minutes" and "3 Jul 2026, 15:20" never collide.
 *
 * Usage:
 *   <DetailList>
 *     <Detail label="Realm">master</Detail>
 *     <Detail label="Expires" sub={absoluteTime(iso, locale)}>{relativeTime(iso)}</Detail>
 *     <Detail label="Session id" mono={id} />
 *   </DetailList>
 */
export interface DetailListProps {
  children: React.ReactNode;
  className?: string;
}

export function DetailList({ children, className }: DetailListProps) {
  return <dl className={`hx-dl${className ? ` ${className}` : ""}`}>{children}</dl>;
}

export interface DetailProps {
  /** The field label (rendered small, uppercase, muted, in its own column). */
  label: React.ReactNode;
  /** The primary value. Omit when the value is only a `mono` technical string (e.g. a session id). */
  children?: React.ReactNode;
  /** A muted secondary line under the value — e.g. a formatted absolute timestamp. */
  sub?: React.ReactNode;
  /** A monospace technical line under the value — e.g. a UUID / subject id. */
  mono?: React.ReactNode;
  /** Vertically center the label against a single-line value (e.g. a chip). Default: top-aligned. */
  center?: boolean;
}

export function Detail({ label, children, sub, mono, center }: DetailProps) {
  const hasMain = children !== undefined && children !== null && children !== false;
  return (
    <div className={`hx-dl__row${center ? " hx-dl__row--center" : ""}`}>
      <dt className="hx-dl__label">{label}</dt>
      <dd className="hx-dl__value">
        {hasMain && <div className="hx-dl__main">{children}</div>}
        {sub !== undefined && sub !== null && sub !== false && <div className="hx-dl__sub">{sub}</div>}
        {mono !== undefined && mono !== null && mono !== false && <div className="hx-dl__mono">{mono}</div>}
      </dd>
    </div>
  );
}
