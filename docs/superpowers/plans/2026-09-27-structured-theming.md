# Structured theming — implementation plan

> For agentic workers: executed task by task (subagent-driven). The spec is
> `docs/superpowers/specs/2026-09-27-structured-theming.md` — it is the source of truth for every value
> (field names, limits, forbidden constructs, endpoints, permissions, tests). This plan only orders the work.

**Goal:** replace free-form realm CSS with a validated theme model rendered by HelixIAM on every
user-facing page and email; restricted custom CSS as escape hatch; file themes; CSP without
`style-src 'unsafe-inline'`.

**Branch:** `feature/structured-theming` (worktree `/Users/mo/work/helixiam/wt-theming`), off master `424d6ff`.
Targets the next minor after 1.0 — never merged into `fix/1.0-blockers`.

## Global constraints
- TDD: write the test, watch it fail, then implement. Tests named in the spec's "Tests" section are mandatory.
- Schema changes: BOTH `helix-iam-server/src/main/resources/schema.sql` AND a new Flyway
  `db/migration/V<n>__*.sql` (next free number; V18 is the last on master). The e2e/Flyway tests must pass
  on both paths: default and `-Dhelix.e2e.schema=sql-init`.
- Admin API: validation → 400 `{message, fieldErrors}` via `AdminValidationAdvice`; never throw into the
  security `/error` path. Every by-id lookup is scoped to the path realm (404 otherwise) — the rc.4
  cross-realm rules (`CrossRealmAdminE2eTest` style).
- Admin permissions: realm theme = `manage-realm`, organization theme = `manage-organizations`
  (`AdminRoutePermissions`). Audit every change (field names changed, never asset bytes).
- DB pool auto-commit is false: tests that write with `JdbcTemplate` use `TransactionTemplate`.
- Log user-controlled values through `io.helixiam.common.log.LogSafe.sanitize`.
- Commits: logical, message says what/why. NEVER any AI attribution (no Co-Authored-By, no "Claude").
  Single-quoted `git commit -m '...'`. Never push.
- Full suite `cd helix-iam-server && mvn -B clean verify` green at the end of every task; plus
  `mvn -B test -Dhelix.e2e.schema=sql-init -Dtest='*E2eTest,Flyway*Test' -Dsurefire.failIfNoSpecifiedTests=false`.

## Tasks

### Task 1 — Theme model, validation, storage, admin API, migration (spec §1, §4 validation, §7)
- `Theme` model (colours light/dark, typography, shape, assets, layout, localised texts, links) +
  validator: `#RRGGBB`, ranges, https-only URLs (or own asset URLs), WCAG AA contrast (ink/surface, text on
  primary) naming the failing pair, dark defaults derived from light.
- `CustomCssValidator` exactly per spec §4 (32 KB, forbidden constructs, `url(` allowlist).
- Storage for realm theme + organization theme (validated JSON column or structured table), Flyway + schema.sql.
- Precedence merge: org (when in context) → realm → HelixIAM default, field by field.
- `GET/PUT /admin/realms/{r}/theme`, `GET/PUT /admin/realms/{r}/organizations/{orgId}/theme`, permissions,
  audit, cross-realm 404.
- Flyway data migration of legacy `primaryColor`, `backgroundColor`, `logoUrl`, `welcomeText`, `customCss`
  (valid CSS kept, invalid dropped + logged); legacy realm-settings fields keep working mapped onto the theme
  and are marked deprecated in OpenAPI.
- Realm import/export carries the theme (import runs the same validation).
- Tests: validation (all spec cases), precedence, cross-realm, migration, import rejection.

### Task 2 — Assets and fonts (spec §3)
- `POST/GET/DELETE /admin/realms/{r}/theme/assets` (DB storage behind a `ThemeAssetStore` interface);
  woff2 ≤ 500 KB ×8, svg (sanitised: no script, no external refs, no foreignObject, no event handlers),
  png, webp with size limits; type checked by content, not just extension.
- Public `/realms/{r}/theme/assets/{id}.{ext}` with correct Content-Type, `nosniff`, Content-Disposition,
  caching; realm-scoped.
- Theme font fields resolve uploaded fonts by name (validated in Task 1's validator hook).
- Tests: size/type limits, malicious SVG corpus, cross-realm, headers.

### Task 3 — Rendering: theme.css, shared head fragment, CSS variables contract, CSP, preview (spec §2, §4 serving, §6)
- `/realms/{r}/theme.css` (+`?org=`): custom properties only (light `:root`, dark media block),
  `@font-face` for uploaded fonts, then validated custom CSS; `text/css`, strong ETag, `max-age=300`, 304.
- One shared head/brand fragment in every user-facing template (list in spec §2) incl. favicon,
  theme-color, logo(s), texts, locale switcher, layout split/centered, legal links.
- Refactor `static/css/*` so every colour/font/radius/spacing reads `--hx-*` variables; remove every
  `<style>` block and `style=""` attribute from templates (move to classes).
- CSP: drop `'unsafe-inline'` from `style-src`; `img-src 'self' data:` + per-realm allowlisted origins.
- `POST /admin/realms/{r}/theme/preview` renders login with the proposed theme without saving.
- Tests: parameterised coverage over EVERY user-facing template (new template without the fragment fails),
  no default HelixIAM wording when themed, XSS through every theme field, CSP header, ETag change, preview.

### Task 4 — Emails (spec §2 emails)
- Verification, reset, magic link, OTP emails use theme logo, colours, texts, footer.
- Tests: rendered email bodies carry the theme.

### Task 5 — File themes + Helm (spec §5)
- `helix.theme.directory`, `themes/{name}/theme.json` + `assets/`; realm `themeName`; DB fields override
  file; same validation at startup and reload; invalid → refused, logged, fallback.
- Helm `themes` value (ConfigMap or existing volume).
- Tests: mounted theme used; invalid falls back and logs; file theme renders identical to the same DB theme.

### Task 6 — Docs, changelog, visual acceptance
- `docs/THEMING.md` (model, CSS variables contract, escape hatch and limits, file themes, migration).
- Changelog entry (security improvement called out).
- Playwright acceptance with the Monthfold reference theme (spec "Reference consumer"): sign-in, MFA
  enrolment, recovery codes, password reset, light AND dark, desktop AND mobile; verification email.
  UI/UX review agent must sign off.
