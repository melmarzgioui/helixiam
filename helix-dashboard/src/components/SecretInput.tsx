/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Badge } from "./Badge";
import { Button } from "./Button";
import { Input, Textarea } from "./FormField";
import { useT } from "../i18n/LocaleContext";

export interface SecretInputProps {
  /** Accessible name of the input (the visible label is the surrounding FormField's). */
  label: string;
  /** What the admin typed (never the stored value: the API does not return it). */
  value: string;
  /** A value is stored on the server (`<key>Set: true`). */
  stored: boolean;
  /** The admin chose Replace. */
  replacing: boolean;
  /** The admin chose Remove (`clear<Key>: "true"` is sent on save). */
  clearing?: boolean;
  multiline?: boolean;
  placeholder?: string;
  onChange: (value: string) => void;
  onReplace: (on: boolean) => void;
  /** Offers Remove for a stored secret; omit where removing makes no sense. */
  onClear?: (on: boolean) => void;
}

/**
 * A write-only identity-provider secret (Task 4): "Set" / "Not set", Replace, Remove, as in the email settings. The
 * stored value is never shown or prefilled; an empty field is never sent, so the API keeps the stored secret; Remove
 * sends `clear<Key>`.
 */
export function SecretInput({
  label, value, stored, replacing, clearing, multiline, placeholder, onChange, onReplace, onClear,
}: SecretInputProps) {
  const { t } = useT();
  const editing = !clearing && (!stored || replacing);
  const pending = !!value.trim() && editing;
  return (
    <div className="hx-secretstate">
      {clearing
        ? <Badge tone="warning">{t("secret.pendingRemove")}</Badge>
        : pending
          ? <Badge tone="accent">{t(stored ? "email.secret.pendingReplace" : "email.secret.pendingNew")}</Badge>
          : stored ? <Badge tone="success">{t("email.secret.set")}</Badge> : <Badge tone="neutral">{t("email.secret.notSet")}</Badge>}
      {editing && (multiline
        ? <Textarea className="hx-mono" value={value} onChange={(e) => onChange(e.target.value)} rows={4} aria-label={label}
            placeholder={placeholder ?? "-----BEGIN PRIVATE KEY-----…"} spellCheck={false} />
        : <Input type="password" value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}
            placeholder={placeholder ?? "••••••••"} autoComplete="new-password" spellCheck={false} />)}
      {stored && !replacing && !clearing && <Button variant="ghost" onClick={() => onReplace(true)}>{t("email.secret.replace")}</Button>}
      {stored && !replacing && !clearing && onClear && <Button variant="ghost" onClick={() => onClear(true)}>{t("secret.remove")}</Button>}
      {stored && replacing && <Button variant="ghost" onClick={() => onReplace(false)}>{t("email.secret.keep")}</Button>}
      {clearing && onClear && <Button variant="ghost" onClick={() => onClear(false)}>{t("secret.undoRemove")}</Button>}
    </div>
  );
}
