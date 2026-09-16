/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from "react";

/** Reactive media-query match — drives the responsive shell (drawer vs fixed sidebar). */
export function useMediaQuery(query: string): boolean {
  const get = () => (typeof window !== "undefined" ? window.matchMedia(query).matches : false);
  const [matches, setMatches] = useState(get);

  useEffect(() => {
    const mql = window.matchMedia(query);
    const onChange = () => setMatches(mql.matches);
    onChange();
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, [query]);

  return matches;
}

/** True below the desktop breakpoint (≈1024px). */
export function useIsCompact(): boolean {
  return useMediaQuery("(max-width: 1023px)");
}
