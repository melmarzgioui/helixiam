# Helix Admin Console

The operator UI for **Helix IAM** — register, configure, and monitor identity-provider
connections (DigiD, eHerkenning, eIDAS, generic SAML2, OIDC) and identity brokers without
editing YAML. This package is the React app **and** its design system.

The design system is the deliverable for **Epic 8.0**: a Storybook built on
**BRANDBOOK_KUBEDNA_V2** tokens, used to assemble the connection wizard (E8.4) and console (E8.5).

## Stack

- React 18 + Vite 5
- Storybook 8 (`@storybook/react-vite`, CSF3) with `addon-essentials` + `addon-a11y`
- TypeScript (strict) + Vitest

## Run

```bash
npm install
npm run storybook      # design system at http://localhost:6006
npm run dev            # app dev server (Vite)
npm run build          # type-check + production build
npm run build-storybook
npm test               # vitest
```

## Design tokens

All visual decisions come from `src/styles/tokens.css` (BRANDBOOK_KUBEDNA_V2):

- **Brand**: Cucumber `#476957` (primary), Jade `#a3d4c4` (dark-mode accent), Black Cat,
  Ink, Willow surfaces. Daylight / Genie blues are **accent-only** and never used in dark mode.
- **Semantic tokens** (`--bg`, `--surface`, `--fg`, `--primary`, `--border`, …) are theme-aware:
  `[data-theme="dark"]` flips to Black Cat surfaces with Jade accents.
- **Type**: Work Sans (UI) + Roboto Mono (URNs / code). **Shape**: `--r-sm` 10px,
  `--r` 14px. **Motion**: `--ease` `cubic-bezier(.22,.61,.36,1)`.

Use the **theme** toolbar in Storybook to toggle light/dark.

## Layout

```
.storybook/            Storybook config (main, preview + theme toolbar)
src/styles/tokens.css  BRANDBOOK_KUBEDNA_V2 design tokens (light + dark)
src/components/        Components (see inventory) + co-located stories
src/stories/           Foundations: Colors, Typography
```

## Component inventory

**Brand** — `Logo` (Helix IAM lockup / wordmark / mark, "by KubeDNA" endorsement).

**Foundations** — Colors, Typography.

**Form** — `Button`, `Input`, `Select` (branded dropdown), `FormField`, `Switch`,
`Checkbox`, `Radio`, `RadioCard`.

**Display** — `Badge`, `Card`, `Table`, `EmptyState`, `Divider`, `Spinner`, `Tooltip`.

**Navigation & layout** — `AppShell` (sidebar + topbar w/ realm switcher + user),
`Tabs`, `Stepper` (wizard progress).

**Overlay & feedback** — `Modal`, `ConfirmDialog`, `Toast`.

Still to build (domain-specific): provider-type tiles + provider logos
(DigiD/eHerkenning/eIDAS/Google/Microsoft/GitHub), LoA badge, metadata-import field,
mapper-row editor.

## Status

E8.0 + E8.0b — design system + core console components in place, reviewed in light/dark via
Playwright. Next: E8.4 connection wizard and E8.5 console, wired to the E8.2 admin REST API.
