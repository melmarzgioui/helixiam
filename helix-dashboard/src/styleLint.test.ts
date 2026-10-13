/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";

// DESIGN_SYSTEM.md "The one rule": no `style={{…}}` in pages/components — layout comes from the Page
// kit, visuals come from components + hx-* classes. The only tolerated inline style is a genuinely
// dynamic value CSS itself can't express (a measured position, an open numeric/length prop, a
// data-driven colour) — and even then it's carried as a CSS *custom property*, never a literal CSS
// property. This test fails the build if `style={` turns up anywhere else in src/.
//
// Read via Vite's `import.meta.glob(..., { query: "?raw" })` (not node:fs) so the test needs no
// @types/node dependency and runs the same way under vitest and in the browser-targeted build.
// Storybook stories (*.stories.tsx) are intentionally excluded from the glob: they're dev-only
// documentation artifacts that render only inside Storybook, never inside the shipped console
// (vite.config.ts's build has exactly two entry points, index.html and account.html, and neither
// imports any story file) — and they often deliberately lay out several raw variants side by side for
// comparison, which is a documentation concern, not a console-UI one. *.test.ts(x) files (including
// this one) are excluded too.
const modules = import.meta.glob("./**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

/**
 * Every entry here is a reviewed, justified exception: the file's `style={` occurrences carry ONLY
 * CSS custom properties, for a value that is genuinely dynamic (a position measured at runtime, an
 * open numeric/length prop used across many call sites, or a per-item colour/size). The number is the
 * exact count of `style={` occurrences expected in that file — if it changes (up OR down), the
 * allow-list is stale and this test fails until a human re-reviews and updates it.
 */
const ALLOWED_DYNAMIC_STYLE: Record<string, number> = {
  "./components/AppShell.tsx": 1, // UserMenu dropdown position — measured from the trigger's bounding rect
  "./components/Combobox.tsx": 1, // option panel position/width — measured from the input's bounding rect
  "./components/Divider.tsx": 2, // open CSS-length `gap` prop (any valid length, caller-supplied)
  "./components/Drawer.tsx": 1, // open CSS-length `width` override prop
  "./components/Modal.tsx": 1, // open numeric `width` prop — dozens of call sites, 420-760px, not a fixed set
  "./components/MultiCombobox.tsx": 1, // option panel position/width — measured from the control's bounding rect
  "./components/ProviderLogo.tsx": 2, // per-provider pixel size + brand colour/gradient (arbitrary CSS paint)
  "./components/RowMenu.tsx": 1, // overflow-menu position — measured from the trigger's bounding rect
  "./components/Select.tsx": 1, // option panel position/width — measured from the trigger's bounding rect
  "./components/Spinner.tsx": 1, // open numeric `size` prop + its derived ring border width
  "./components/Table.tsx": 1, // open per-column `width` prop (author-supplied, not a fixed set of sizes)
  "./pages/EidAssurancePage.tsx": 1, // per-scheme accent colour (--tone), data-driven
  "./pages/GroupsPage.tsx": 1, // tree-row indent depth (--depth), data-driven
};

function isScannable(path: string): boolean {
  return !path.endsWith(".stories.tsx") && !path.includes(".test.");
}

describe("design system: no inline styles in src/ (except reviewed dynamic-value exceptions)", () => {
  it("every `style={` in src/ is in ALLOWED_DYNAMIC_STYLE and carries only CSS custom properties", () => {
    const offenders: string[] = [];
    const seen = new Set<string>();

    for (const [path, content] of Object.entries(modules)) {
      if (!isScannable(path)) continue;
      const count = (content.match(/style=\{/g) ?? []).length;
      if (count === 0) continue;

      seen.add(path);
      const allowed = ALLOWED_DYNAMIC_STYLE[path];
      if (allowed === undefined) {
        offenders.push(
          `${path}: ${count} inline style(s) found, but this file is not in ALLOWED_DYNAMIC_STYLE. ` +
            `Move it to a hx-* class in components.css, or — if it's a genuinely dynamic value CSS ` +
            `can't express — carry it as a CSS custom property and add a reviewed, justified entry here.`,
        );
      } else if (allowed !== count) {
        offenders.push(
          `${path}: found ${count} inline style(s), but ALLOWED_DYNAMIC_STYLE expects ${allowed}. ` +
            `The exception list is stale — review the new/removed usage and update the count (and the ` +
            `comment explaining why it's a justified dynamic value).`,
        );
      } else if (!content.includes("--")) {
        // Weak but meaningful: every justified exception sets a "--custom-property" somewhere in the
        // file. A file with no "--" at all is almost certainly carrying a literal CSS property instead.
        offenders.push(`${path}: allow-listed but contains no CSS custom property ("--…") — only custom-property exceptions are allowed here.`);
      }
    }

    // A file that was allow-listed but has since been fully cleaned up should be removed from the list,
    // so the allow-list never silently grows stale in the other direction either.
    for (const path of Object.keys(ALLOWED_DYNAMIC_STYLE)) {
      if (!seen.has(path)) offenders.push(`${path}: allow-listed in ALLOWED_DYNAMIC_STYLE but has no inline style left — remove this entry.`);
    }

    expect(offenders, `\n${offenders.join("\n")}`).toEqual([]);
  });
});
