import React from "react";

/** A small, icon-only copy-to-clipboard button that flips to a checkmark for ~1.2s after copying. */
export function CopyButton({ value, label = "Copy", size = 30 }: { value: string; label?: string; size?: number }) {
  const [copied, setCopied] = React.useState(false);
  const copy = () => navigator.clipboard?.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); });
  return (
    <button type="button" aria-label={copied ? "Copied" : label} title={copied ? "Copied" : label} onClick={copy}
      style={{
        flexShrink: 0, width: size, height: size, border: "1px solid var(--border)", borderRadius: "var(--r-sm)",
        background: "transparent", cursor: "pointer", color: copied ? "var(--accent)" : "var(--fg-muted)",
        display: "inline-flex", alignItems: "center", justifyContent: "center",
      }}>
      {copied
        ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" /></svg>
        : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" strokeWidth="1.8" /><path d="M5 15V5a2 2 0 012-2h10" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>}
    </button>
  );
}
