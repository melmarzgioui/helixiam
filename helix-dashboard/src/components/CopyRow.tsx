/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { CopyButton } from "./CopyButton";

/** A read-only label + monospace value with a copy-to-clipboard icon (used for endpoint/URL lists). */
export function CopyRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="hx-copyrow">
      <span className="hx-copyrow__label">{label}</span>
      <code className="hx-copyrow__value" title={value}>{value}</code>
      <CopyButton value={value} label={`Copy ${label}`} />
    </div>
  );
}
