/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

/**
 * After a failed save, call the returned function to move focus to the first invalid field — the one carrying
 * `aria-invalid="true"` (FormField sets this automatically whenever it's given an `error`) — once any state update
 * that reveals it (e.g. switching to the tab that field lives on) has rendered. Scrolls it into view first, so the
 * banner being a screen away from the field is never the only sign something's wrong.
 *
 * Scoped to `root` when given (a form with several independent sections can target just its own), otherwise scans
 * the whole document — which is also what to use right after a state update (like a tab switch) moves the invalid
 * field into a part of the DOM the root ref doesn't cover yet.
 */
export function useFocusInvalid(root?: React.RefObject<HTMLElement | null>): () => void {
  const [tick, setTick] = React.useState(0);

  React.useEffect(() => {
    if (!tick) return;
    const scope: ParentNode = root?.current ?? document;
    const first = scope.querySelector<HTMLElement>('[aria-invalid="true"]');
    if (!first) return;
    first.scrollIntoView({ block: "center", behavior: "smooth" });
    first.focus({ preventScroll: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  return React.useCallback(() => setTick((n) => n + 1), []);
}
