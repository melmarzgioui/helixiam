// Helix admin console — tiny i18n core (no runtime dependency).
//
// translate(locale, key, params?) resolves a key against the locale's dictionary, falling back to the
// English (source) dictionary, and finally to the key itself — so a missing translation is always
// visible (and harmless) rather than a crash or a blank.

import { DICTIONARIES, en, type Dict, type Locale } from "./dictionaries";

export type { Locale };
export { LOCALES } from "./dictionaries";

/** localStorage key under which the chosen UI locale persists across reloads. */
export const LOCALE_STORAGE_KEY = "helix.locale";

const SUPPORTED: Locale[] = ["en", "nl"];

/** Narrow an arbitrary string (cookie / localStorage / navigator) to a supported Locale, else "en". */
export function normalizeLocale(raw: string | null | undefined): Locale {
  if (!raw) return "en";
  const lang = raw.toLowerCase().split("-")[0];
  return (SUPPORTED as string[]).includes(lang) ? (lang as Locale) : "en";
}

/**
 * Resolve `key` for `locale`. Order: locale dict -> English dict -> the key itself.
 * Supports simple `{name}` interpolation via the optional `params`.
 */
export function translate(
  locale: Locale,
  key: string,
  params?: Record<string, string | number>,
): string {
  const dict: Dict = DICTIONARIES[locale] ?? en;
  const raw = dict[key] ?? en[key] ?? key;
  if (!params) return raw;
  return raw.replace(/\{(\w+)\}/g, (_m, name: string) =>
    name in params ? String(params[name]) : `{${name}}`,
  );
}

/** Pick the initial locale: persisted choice > browser language > "en". */
export function detectInitialLocale(): Locale {
  if (typeof window !== "undefined") {
    const stored = window.localStorage?.getItem(LOCALE_STORAGE_KEY);
    if (stored) return normalizeLocale(stored);
    const nav = window.navigator?.language;
    if (nav) return normalizeLocale(nav);
  }
  return "en";
}
