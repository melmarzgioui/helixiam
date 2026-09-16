/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Shared date/time formatting helpers for the console.
//
// Timestamps in the UI read best as TWO distinct pieces: a prominent relative value
// ("in 14 minutes", "3 minutes ago") and a muted, human-formatted absolute value
// ("3 Jul 2026, 15:20"). Rendering the raw ISO string (with nanoseconds + trailing Z)
// next to the relative value is unreadable — these helpers keep them separate and tidy.

import type { Locale } from "../i18n/dictionaries";

const INTL_LOCALE: Record<Locale, string> = { en: "en-GB", nl: "nl-NL" };

/** A compact, humanised relative time: "in 14m", "3h 2m ago", "just now". Locale-agnostic units. */
export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const ms = t - Date.now();
  const abs = Math.abs(ms);
  if (abs < 45_000) return "just now";
  const d = Math.floor(abs / 86_400_000);
  const h = Math.floor((abs % 86_400_000) / 3_600_000);
  const m = Math.floor((abs % 3_600_000) / 60_000);
  const span = d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
  return ms >= 0 ? `in ${span}` : `${span} ago`;
}

/** A clean, locale-aware absolute timestamp: "3 Jul 2026, 15:20" — no raw ISO, no nanoseconds. */
export function absoluteTime(iso: string | null | undefined, locale: Locale = "en"): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  try {
    return new Intl.DateTimeFormat(INTL_LOCALE[locale] ?? "en-GB", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(date);
  } catch {
    return date.toISOString();
  }
}
