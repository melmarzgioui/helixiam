/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Helix admin console — React locale context + the useT() hook.
//
// Wrap the app (or any subtree) in <LocaleProvider>; call useT() to get a bound t(key, params?) plus
// the current locale and a setLocale that persists the choice. If a component renders outside a
// provider, useT() still works (defaults to "en") so it degrades gracefully.

import React from "react";
import {
  LOCALE_STORAGE_KEY,
  detectInitialLocale,
  translate,
  type Locale,
} from "./i18n";

export interface LocaleContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: string, params?: Record<string, string | number>) => string;
}

const LocaleContext = React.createContext<LocaleContextValue | null>(null);

export interface LocaleProviderProps {
  /** Force an initial locale (tests / Storybook); otherwise detected from storage + browser. */
  initialLocale?: Locale;
  children: React.ReactNode;
}

export function LocaleProvider({ initialLocale, children }: LocaleProviderProps) {
  const [locale, setLocaleState] = React.useState<Locale>(
    () => initialLocale ?? detectInitialLocale(),
  );

  const setLocale = React.useCallback((next: Locale) => {
    setLocaleState(next);
    try {
      window.localStorage?.setItem(LOCALE_STORAGE_KEY, next);
    } catch {
      /* storage may be unavailable (private mode / SSR) — non-fatal */
    }
    if (typeof document !== "undefined") {
      document.documentElement.lang = next;
    }
  }, []);

  const value = React.useMemo<LocaleContextValue>(
    () => ({
      locale,
      setLocale,
      t: (key, params) => translate(locale, key, params),
    }),
    [locale, setLocale],
  );

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

/** Bound translation hook. Works outside a provider too (defaults to "en"). */
export function useT(): LocaleContextValue {
  const ctx = React.useContext(LocaleContext);
  if (ctx) return ctx;
  return {
    locale: "en",
    setLocale: () => {},
    t: (key, params) => translate("en", key, params),
  };
}
