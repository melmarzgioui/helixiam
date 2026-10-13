/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

/** A small, icon-only copy-to-clipboard button that flips to a checkmark for ~1.2s after copying. */
export function CopyButton({ value, label = "Copy", size = 30 }: { value: string; label?: string; size?: number }) {
  const [copied, setCopied] = React.useState(false);
  const copy = () => navigator.clipboard?.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); });
  return (
    <button type="button" aria-label={copied ? "Copied" : label} title={copied ? "Copied" : label} onClick={copy}
      className={`hx-copybtn${size >= 38 ? " hx-copybtn--lg" : ""}${copied ? " hx-copybtn--copied" : ""}`}>
      {copied
        ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" /></svg>
        : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" strokeWidth="1.8" /><path d="M5 15V5a2 2 0 012-2h10" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>}
    </button>
  );
}
