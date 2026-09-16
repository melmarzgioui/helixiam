# Helix Admin Console — Design System (the kit contract)

Every page derives from this. The goal: **uniform look & feel, one structure, easy to maintain, light pages.**
If you need a style that isn't here, add it to the kit (a component or a `hx-*` class) — **never inline it on a page.**

## The one rule

> **No `style={{…}}` in pages.** Layout comes from the Page kit; visuals come from components + `hx-*` classes.
> The only tolerated inline style is a *dynamic value that can't be a class* (e.g. a computed width from data) — and even then, prefer a CSS custom property.

## Files
- `src/styles/tokens.css` — colours, type, radius, shadow, **spacing scale** (`--sp-1..6`, `--card-px/py`, `--stack-gap`, `--field-gap`, `--label-gap`). Light + dark.
- `src/styles/components.css` — every component's CSS + the page-layout kit + Alert. Class-based so hover/focus/motion work.
- `src/styles/app.css` — shell, sidebar, topbar, table, rowcard, page rhythm.

## Page skeleton — copy this

```tsx
import { Page, PageHeader, PageBody, Section, PageToolbar } from "../components/Page";
import { Button } from "../components/Button";
import { Alert } from "../components/Alert";

export function ThingPage({ api, realmId }: Props) {
  return (
    <Page>
      <PageHeader
        title="Things"
        description="One-line explanation of what this page manages."
        actions={<Button variant="primary" onClick={create}>Create thing</Button>}
      />
      <PageBody>
        {error && <Alert tone="danger" title="Couldn't load things">{error}</Alert>}
        <Section title="All things" description="Optional section subtitle.">
          {/* table / list / fields */}
        </Section>
      </PageBody>
    </Page>
  );
}
```

- `PageBody` = the canonical vertical stack (gap `--stack-gap`). Use `layout="grid"` for a responsive 2-col detail grid.
- `Section` = titled card with header strip + padded body. `layout="cols"` flows fields side-by-side.
- `Card` = plain surface card (no header strip). Use for simple grouped content.

## Components (import from `../components/*`) — use these, don't rebuild
- **Layout:** `Page`, `PageHeader`, `PageBody`, `Section`, `PageToolbar`, `Card`, `Divider`
- **Actions:** `Button` (`variant="primary|ghost|danger"`), `RowMenu`, `CopyButton`
- **Forms:** `FormField`, `Input`, `Textarea`, `Select`, `Switch`, `Choice` (checkbox/radio)
- **Feedback:** `Alert` (in-page banner), `Toast` (transient — put in a `.hx-toasthost` fixed region), `Spinner`, `EmptyState`
- **Data:** `Table` (or `.hx-table` inside `.hx-tablescroll`), `Badge`, `Tooltip`, `Tabs`, `Stepper`, `Modal` / `ConfirmDialog`

## Feedback: error / warning / info / success
- **Inline banner** on the page → `<Alert tone="danger|warning|info|success" title="…">body</Alert>`.
- **Transient** after an action → `<Toast tone="error|success|info" …/>` inside a `<div className="hx-toasthost">`.
- **Field error** → `<FormField error="…">`.
- Never hand-roll a coloured box.

## Spacing (uniform everywhere) — use tokens, never magic px
- Between stacked cards/sections: `--stack-gap` (16px) — free via `PageBody`.
- Card/section padding: `--card-px` / `--card-py` — free via `Section`/`Card`.
- Between form fields: `--field-gap`; label→control `--label-gap`; control→hint `--help-gap` — free via `FormField`.
- Small clusters (badges, inline buttons): `--sp-2` (8px). Toolbar gaps: `--sp-3` (12px).
- Utility classes when you must: `.hx-badges`, `.hx-namecell`, `.hx-toolbar`, `.hx-muted`, `.hx-faint`, `.hx-help`, `.hx-mono`.

## Loading / empty
- Loading: `<div className="hx-loadwrap"><Spinner size={28} label="Loading…" /></div>`.
- Empty: `<EmptyState title="No things yet" message="…" action={<Button…/>} />`.

## Do / Don't
| Do | Don't |
|---|---|
| `<Page><PageHeader/><PageBody>…` | a bare `<div>` with an inline `hx-pagehead` copy |
| `<Section title="…">` | `<div className="hx-card" style={{padding…}}>` |
| `<Alert tone="danger">` | `<div style={{background:'#fdecec'…}}>` |
| spacing via tokens/`PageBody`/`FormField` | `style={{ marginBottom: 16 }}` |
| add a `hx-*` class to components.css | one-off inline styles repeated across pages |

## Verifying a page
- `npx tsc -b` clean, `npx vitest run` green.
- `grep -c "style={{" src/pages/YourPage.tsx` → **0** (or only a justified dynamic value).
- Page renders under `<Page>` with a single `<PageHeader>`.
- Playwright: loads at desktop (1440) + mobile (390) with no console errors; header, body spacing and any table/form look identical to sibling pages.
