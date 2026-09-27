# Theming

HelixIAM themes every user-facing page from structured, validated settings: the sign-in and registration pages,
two-step enrolment and entry, recovery codes, password reset, consent, device activation, required actions, magic
link, the flow pages, the maintenance page and the account console. The emails use the same settings too. You do not
need to write CSS. A restricted custom-CSS escape hatch remains for the few things the model does not cover.

This page is for operators and integrators. It covers:

1. [Overview](#1-overview)
2. [The theme model](#2-the-theme-model)
3. [Admin API](#3-admin-api)
4. [CSS variables contract (v1)](#4-css-variables-contract-v1)
5. [`theme.css`](#5-themecss)
6. [Custom CSS: the escape hatch](#6-custom-css-the-escape-hatch)
7. [File themes](#7-file-themes)
8. [Content-Security-Policy](#8-content-security-policy)
9. [Emails](#9-emails)
10. [Import and export](#10-import-and-export)
11. [Migrating from 1.0](#11-migrating-from-10)
12. [Known limitations](#12-known-limitations)
13. [Where the implementation differs from the design spec](#13-where-the-implementation-differs-from-the-design-spec)

The examples use the realm `acme` and these shell variables:

```bash
HX=https://idp.example.com          # IDP_BASE_URL
# An admin token, e.g. from the bootstrap service account (HELIX_BOOTSTRAP_CLIENT_ID, see README "Configuration")
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials \
  "$HX/realms/master/oauth2/token" | jq -r .access_token)
AUTH="Authorization: Bearer $TOKEN"
```

A bearer token needs no CSRF header. A console session (cookie) does: send `X-XSRF-TOKEN` on every write.

---

## 1. Overview

### Layers

The theme a page gets is built from layers, merged **field by field**. The top layer wins:

| Order | Layer | Where it comes from |
|---|---|---|
| 4 (top) | Organization theme | `PUT /admin/realms/{r}/organizations/{orgId}/theme`. Applies only while that organization is in context. |
| 3 | Realm theme | `PUT /admin/realms/{r}/theme` (stored in the database) |
| 2 | File theme (optional) | A theme directory mounted from `helix.theme.directory`, selected with `PUT /admin/realms/{r}/theme/base` |
| 1 (bottom) | Built-in default | The HelixIAM look |

A field that a layer leaves out (or sets to `null`) is inherited from the layer below. Database fields therefore
override file-theme values, and an organization overrides only the fields it sets.

An organization is **in context** when the sign-in started with `organization=<id or name>` on `/oauth2/authorize`
and that organization is enabled and belongs to the realm. It stays in context for the rest of that sign-in (login,
two-step, consent), and the emails sent during it use it too. An organization of another realm never applies.

Merge rules:

- **Colours:** a layer that sets a colour's `light` value replaces the whole colour. Its `dark` value is then the
  layer's own `dark`, or it is derived. So an organization's primary colour is never paired with the realm's dark
  primary. A layer that sets only `dark` keeps the `light` value from below.
- **Lists and localised texts** are single values. An organization that sets `texts.footerText` replaces the realm's
  footer text **for every locale**, not only for the locales it lists (see [known limitations](#12-known-limitations)).
- **Custom CSS** can only be set on the realm layer (or in a file theme).

### What "branded" means

A page is **branded** as soon as any layer above the built-in default sets anything: a file theme, the realm theme or
the organization theme. On a branded page:

- the HelixIAM wordmark, favicon and brand-panel artwork (watermark, lines, sparks) are **not** shown;
- without a `logoUrl`, the page shows a **name as text** in place of a logo: the organization's display name when an
  organization is in context, otherwise the realm's display name (`displayName` in
  `PUT /admin/realms/{r}/settings`). With neither, no name is shown;
- the page title is `<name> — <page>`, for example `Acme — Sign in`;
- without a `faviconUrl`, the page sets no favicon at all (it does not fall back to the HelixIAM icon).

**Set the realm's display name** when you brand a realm; titles and the text logo use whatever display name the
realm has, or no name at all when it has none.

- the brand-panel texts you do not set (`brandHeadline`, `brandSubhead`, `brandByline`, `brandBadges`) are
  **hidden**: HelixIAM's panel copy ("Secure access for every human and machine.", the "Self-hosted identity"
  byline and the OpenID Connect / SAML 2.0 / SCIM / Passkeys badges) appears only on unbranded pages. The panel then
  shows just the logo or name. See [Texts](#texts).

---

## 2. The theme model

A theme is one JSON object. Every group and every field is optional. The same schema is used by
`PUT /admin/realms/{r}/theme`, the organization theme, the preview, realm import/export and file themes
(`theme.json`).

A complete realm theme:

```json
{
  "colors": {
    "primary":       {"light": "#1d4ed8", "dark": "#93b4f5"},
    "primaryStrong": {"light": "#1e40af"},
    "surface":       {"light": "#f8fafc"},
    "surfaceRaised": {"light": "#ffffff"},
    "ink":           {"light": "#0f172a"},
    "inkMuted":      {"light": "#475569"},
    "negative":      {"light": "#b91c1c"},
    "positive":      {"light": "#047857"}
  },
  "typography": {"fontSans": "system-sans", "fontDisplay": "system-serif", "baseSize": 16},
  "shape": {"radius": 6, "density": "comfortable"},
  "assets": {"logoUrl": "https://cdn.acme.example/logo.svg"},
  "layout": {"layout": "split", "showLanguageSwitcher": true, "supportedLocales": ["en", "nl"]},
  "texts": {
    "brandHeadline": {"default": "Sign in to Acme", "nl": "Inloggen bij Acme"},
    "brandSubhead": "",
    "brandByline": "",
    "brandBadges": [],
    "footerText": "Acme Inc."
  },
  "links": {"privacyUrl": "https://acme.example/privacy", "termsUrl": "https://acme.example/terms"}
}
```

### Colours

`colors` has 14 roles. Each is `{"light": "#RRGGBB", "dark": "#RRGGBB"}`, and both halves are optional.

| Role | Used for |
|---|---|
| `primary` | Primary buttons, accents, the focused field border, the organization name |
| `primaryStrong` | Links, card titles, button hover |
| `primaryTint` | Secondary (Cancel/Back) buttons, hover tints |
| `surface` | Page background, header bar, form panel, `<meta name="theme-color">` |
| `surfaceRaised` | Cards and input fields. It is also the **text colour on primary** (buttons). |
| `surfaceSunken` | Code blocks, recessed areas |
| `ink` | Body text and headings |
| `inkMuted` | Secondary text, placeholders |
| `border` | Card borders and hairlines |
| `negative` | Error text and error field borders |
| `negativeTint` | Error backgrounds |
| `positive` | Success text |
| `positiveTint` | Success backgrounds |
| `focusRing` | The keyboard focus ring |

Rules:

- A value must be exactly `#RRGGBB` (six hex digits). `#fff`, `rgb()` and names are refused. The case you send is
  kept in the stored theme; `theme.css` prints it in lower case.
- **Dark values are optional.** A missing `dark` value is derived from `light`: the hue is kept, surfaces become
  near-black, ink near-white and brand colours lighter, and derived text colours are adjusted until they reach 4.5:1
  on their dark background. A `dark` value you set is never changed.
- **Unset supporting roles follow your palette.** When a theme sets any of its own main colours, these roles, if left
  unset, are derived from the theme's colours rather than keeping HelixIAM's defaults:
  - `border`: 12 % ink in surface (16 % in dark);
  - `focusRing`: `primary`;
  - `primaryTint`, `negativeTint`, `positiveTint`: 12 % of the colour in `surfaceRaised` (18 % in dark);
  - `surfaceSunken`: 4 % ink in surface (dark: surface darkened by 30 %).
  - `primaryStrong`: `primary` 18 % darker (light) / 20 % lighter (dark), adjusted until the text on it
    (`surfaceRaised`) and its use as a link on `surface` reach 4.5:1.
- `negative` and `positive` keep HelixIAM's red and green when unset, and `inkMuted` HelixIAM's muted ink, but their
  lightness is adjusted until they reach 4.5:1 on your `surface` and `surfaceRaised`. A derived dark `inkMuted` reaches
  4.5:1 on both dark surfaces too. An `inkMuted` you set is never adjusted.
- The split layout's **brand panel** has no colour field of its own. It is derived (see `--hx-brand-*` in the
  [variables contract](#4-css-variables-contract-v1)): in light mode it inverts the page (ground `ink`, text
  `surface`); in dark mode the ground is 14 % of the dark `primary` in the dark `surfaceSunken`, with `ink` text.

### Contrast (WCAG AA)

Saving a layer that changes colours checks the contrast of these pairs on the **effective** theme (the layers below
plus the new layer, with dark values derived). Each pair needs at least 4.5:1:

| Error key | Text | Background | Checked when the saved layer sets |
|---|---|---|---|
| `contrast.inkOnSurface.light` / `.dark` | `ink` | `surface` | `ink` or `surface` |
| `contrast.textOnPrimary.light` / `.dark` | `surfaceRaised` | `primary` | `surfaceRaised` or `primary` |
| `contrast.inkMutedOnSurface.light` / `.dark` | `inkMuted` | `surface` | `inkMuted` or `surface` |
| `contrast.inkMutedOnSurfaceRaised.light` / `.dark` | `inkMuted` | `surfaceRaised` | `inkMuted` or `surfaceRaised` |
| `contrast.brandPanel.dark` | `ink` (dark) | the dark brand-panel ground | `ink`, `surface`, `surfaceSunken` or `primary` |

A pair is only checked when the layer you save sets one of its colours, so a layer that only changes the logo is
never blamed for the colours below it. A failure is a `400`, not a warning. The ratio is rounded down to one decimal:

```json
{
  "message": "Ink on surface (light): ink #aaaaaa on surface #f6f1e9 has a contrast of 2.0:1; WCAG AA needs at least 4.5:1.",
  "fieldErrors": {
    "contrast.inkOnSurface.light": "Ink on surface (light): ink #aaaaaa on surface #f6f1e9 has a contrast of 2.0:1; WCAG AA needs at least 4.5:1.",
    "contrast.textOnPrimary.light": "Text on primary (light): surfaceRaised #ffffff on primary #ffff00 has a contrast of 1.0:1; WCAG AA needs at least 4.5:1."
  }
}
```

The muted-text messages read `Muted text on surface (light): inkMuted #9a9a9a on surface #f6f1e9 has a contrast of
2.5:1; WCAG AA needs at least 4.5:1.` and `Muted text on raised surface (light): inkMuted … on surfaceRaised …`.

The brand-panel message reads `Brand panel text (dark): ink.dark #…… on the brand panel ground #…… has a contrast of
N:1; WCAG AA needs at least 4.5:1.`

### Typography

| Field | Type | Allowed values | Default |
|---|---|---|---|
| `typography.fontSans` | string | A built-in stack, or the exact name of a font family uploaded to the realm (or shipped in its file theme) | `helix-sans` |
| `typography.fontDisplay` | string | Same as `fontSans`. Used for headings and the wordmark. | `helix-sans` |
| `typography.baseSize` | integer | 14–18 (px) | `16` |

Built-in stacks:

| Name | Stack |
|---|---|
| `helix-sans` | `"Work Sans"` (bundled with HelixIAM), then the system sans stack |
| `system-sans` | `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` |
| `system-serif` | `ui-serif, Georgia, Cambria, "Times New Roman", Times, serif` |
| `system-mono` | `ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace` |

- **Uploaded fonts** are referred to by their family name, exactly as uploaded (case-sensitive). They render as
  `"<name>", <system-sans stack>`, and `theme.css` gets one `@font-face` per uploaded file of that family. See
  [Assets](#assets-upload-list-delete).
- **`baseSize` scales every text size.** The root font size is 0.75 × `baseSize` (12 px at the default 16), and text
  sizes are in `rem`. That reproduces the 1.0 pages at the default.
- **Heading weight** follows the display font: 800 for `helix-sans`, 700 for other sans fonts, 600 for serif and mono
  fonts. Heading letter-spacing is −0.02em, or −0.005em for serif and mono. An uploaded family counts as serif when its
  name contains "serif" and not "sans", and as mono when it contains "mono". The weight is guessed from the family name;
  there is no field for it.

### Shape

| Field | Type | Allowed values | Default |
|---|---|---|---|
| `shape.radius` | integer | 0–16 (px). Inputs and cards use fractions of it. | `8` |
| `shape.density` | string | `comfortable` (4 px spacing unit) or `compact` (3 px) | `comfortable` |

### Assets

| Field | Used for |
|---|---|
| `assets.logoUrl` | The logo, on every page and in emails |
| `assets.logoDarkUrl` | The logo in dark mode (`<picture>` with `prefers-color-scheme: dark`). On the split layout's brand panel, which is dark in both schemes, it is used in both schemes when set. |
| `assets.faviconUrl` | The favicon |
| `assets.brandImageUrl` | An optional image on the split layout's brand panel |

Each value must be one of:

- an absolute `https` URL with a host, at most 2048 characters, with no user info and none of these characters:
  whitespace, `"`, `'`, `<`, `>`, `(`, `)`, `\`, `` ` ``, `{`, `}`, `|`, `^`;
- one of the realm's own uploaded images, `/realms/{realm}/theme/assets/{id}.{svg|png|webp}`, which must exist.

An https logo's origin is added to that realm's `img-src` (see [CSP](#8-content-security-policy)).

### Layout

| Field | Type | Allowed values | Default |
|---|---|---|---|
| `layout.layout` | string | `split` (brand panel next to the form) or `centered` (form only, logo above it) | `split` |
| `layout.showLanguageSwitcher` | boolean | | `true` |
| `layout.supportedLocales` | array of strings | 1–20 distinct language tags such as `en`, `nl`, `pt-BR` | `["en", "nl"]` |

- The split/centered choice applies to the sign-in and registration pages. Every other page is a card page with a
  header and footer.
- The language switcher is shown only when `showLanguageSwitcher` is `true` **and** there are at least two locales,
  and only on the sign-in and registration pages.
- **`supportedLocales` decides the page language.** The locale from `?lang=`, the language cookie or
  `Accept-Language` is limited to this list, falling back to the first entry. An English-only realm serves English
  to a Dutch browser. A realm may list a language HelixIAM has no messages for: its theme texts are then used, and
  the built-in messages fall back to English. The organization in context's list applies when it sets one.

### Texts

All texts are **plain text** and are always escaped when rendered.

| Field | Max length | Where |
|---|---|---|
| `texts.brandHeadline` | 120 | Brand panel (split layout) |
| `texts.brandSubhead` | 240 | Brand panel |
| `texts.brandByline` | 120 | Brand panel, bottom |
| `texts.welcomeText` | 500 | Above the sign-in and registration forms |
| `texts.footerText` | 500 | Footer of every page, and emails |
| `texts.brandBadges` | at most 8 badges of 40 characters | Brand panel |

- Each text is either a string (the same for every language) or an object of locale to text. The key `default` is
  the fallback:

  ```json
  {"brandHeadline": {"default": "Sign in to Acme", "nl": "Inloggen bij Acme", "pt-BR": "Entrar na Acme"}}
  ```

  For a page in `nl-BE` the lookup is `nl-BE`, then `nl`, then `default`. If nothing matches, the built-in message is
  used.
- `brandBadges` is an array, or an object of locale to array.
- **Unset (`null`) means the built-in text on an unbranded page and hidden on a branded one** (brand-panel texts and
  badges; see [What "branded" means](#what-branded-means)); `""` hides the text; `[]` hides the badges.
- Refused: `<` and `>`; control characters other than a newline; bidirectional embedding, override and isolate
  characters (U+202A–U+202E, U+2066–U+2069); U+200B and U+FEFF. Locale keys must be `default` or a language tag, at
  most 21 keys.

### Links

| Field | Where |
|---|---|
| `links.privacyUrl` | Page footer, emails |
| `links.termsUrl` | Page footer, emails, and the terms sentence on the registration page |
| `links.supportUrl` | Page footer, emails |

Each must be an `https` URL (same rules as asset URLs). On a branded realm without `termsUrl` the registration page's
terms sentence has no link.

### Custom CSS

`customCss` (string) is the escape hatch. It is allowed on the realm layer only. See [section 6](#6-custom-css-the-escape-hatch).

---

## 3. Admin API

All paths are under `/admin/realms/{realm}`. Errors on writes are `400 {message, fieldErrors}`; the keys of
`fieldErrors` are JSON paths such as `colors.primary.light`, `assets.logoUrl` or `contrast.inkOnSurface.dark`, and
`message` repeats the first error. An unknown realm is a `404`.

### Permissions

| Endpoints | Needs |
|---|---|
| `/theme`, `/theme/preview`, `/theme/assets`, `/theme/base` | `manage-realm` |
| `/organizations/{orgId}/theme` | `manage-organizations` |

An organization outside the path realm is a `404`, also for an admin of that other realm. A `manage-organizations`
admin cannot read or change the realm theme, and a `manage-realm` admin cannot read or change organization themes
unless they also hold `manage-organizations`.

### Strict input

Theme bodies are parsed strictly. An unknown field is a `400` naming its path, so a typo is never silently dropped:

```json
{"message": "Unknown field.", "fieldErrors": {"colors.primry": "Unknown field."}}
```

A value of the wrong type (for example a string for `colors.primary`) is `"Invalid value."` on its path. The
read-only response fields `notices` and `version` are accepted and ignored, so the body of a `GET` can be sent back as
a `PUT`.

### Realm theme

```bash
# The stored realm layer (only what the realm sets; {} when nothing)
curl -s -H "$AUTH" "$HX/admin/realms/acme/theme"

# The effective theme: every layer merged, dark values derived, plus its version
curl -s -H "$AUTH" "$HX/admin/realms/acme/theme?effective=true"

# Replace the realm layer (the whole layer: fields you leave out are cleared, not kept)
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  --data @acme-theme.json "$HX/admin/realms/acme/theme"

# Clear the realm layer
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' -d '{}' "$HX/admin/realms/acme/theme"
```

- `PUT` replaces the stored layer and returns it. There is no `DELETE`; `PUT {}` clears the layer.
- Responses carry `notices` when custom CSS is set (see [section 6](#6-custom-css-the-escape-hatch)).
- `?effective=true` adds `version`, the SHA-256 of the effective theme.

### Organization theme

```bash
ORG_ID=...   # from GET /admin/realms/acme/organizations

curl -s -H "$AUTH" "$HX/admin/realms/acme/organizations/$ORG_ID/theme"
curl -s -H "$AUTH" "$HX/admin/realms/acme/organizations/$ORG_ID/theme?effective=true"

curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"colors": {"primary": {"light": "#7c3aed"}}, "assets": {"logoUrl": "https://cdn.acme.example/northwind.svg"}}' \
  "$HX/admin/realms/acme/organizations/$ORG_ID/theme"
```

- The same model and validation as the realm theme, except that `customCss` is refused
  (`"Custom CSS can only be set on the realm theme."`).
- The effective view is organization, then realm, then default. It leaves out the realm's custom CSS.
- Fonts and images belong to the realm; an organization theme can use any of them.

### Preview

Renders the sign-in page with a proposed **realm** theme, without saving anything.

```bash
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  --data @acme-theme.json "$HX/admin/realms/acme/theme/preview" > preview.html
```

- The body is a theme exactly as for `PUT /theme`, with the same strict parsing and validation (`400` on errors).
  It is validated and merged against the realm's current lower layers (default and file theme).
- The answer is HTML (`Cache-Control: no-store`). The generated stylesheet is carried in the page as a `data:` URL
  allowed by a per-response nonce, and the page repeats its CSP in a `<meta>` tag and sets `<base>` to the server
  origin (`IDP_BASE_URL`, else the request's origin). You can therefore show it in an `iframe srcdoc`; use
  `<iframe sandbox srcdoc=…>` without `allow-scripts`. Scripts and form posts are disabled in the preview.
- It does not touch the stored theme, the caches, the session or the CSRF cookie. It is not audited.
- Only realm themes, and only the sign-in page, can be previewed.

### Assets (upload, list, delete)

Fonts and images are uploaded per realm and served from HelixIAM's own origin.

```bash
# Upload a font (woff2). name = the family name the theme will use; weight defaults to 400, style to normal.
curl -s -H "$AUTH" -F file=@PublicSans.woff2 -F 'name=Public Sans' -F 'weight=100 900' \
  "$HX/admin/realms/acme/theme/assets"

# Upload an image (svg, png or webp); name is optional (defaults to the file name without extension)
curl -s -H "$AUTH" -F file=@logo.svg "$HX/admin/realms/acme/theme/assets"

# List (metadata only, never bytes)
curl -s -H "$AUTH" "$HX/admin/realms/acme/theme/assets"

# Delete
curl -s -X DELETE -H "$AUTH" "$HX/admin/realms/acme/theme/assets/$ASSET_ID"
```

An upload answers `201` with the metadata:

```json
{"id": "5f0c…", "kind": "image", "name": "logo", "ext": "svg", "contentType": "image/svg+xml",
 "size": 1834, "sha256": "…", "created": "…", "url": "/realms/acme/theme/assets/5f0c….svg"}
```

Put the `url` in the theme (`assets.logoUrl`, a custom-CSS `url()`), or, for a font, its `name` in
`typography.fontSans` / `fontDisplay`.

**Limits:**

| Type | Max size | Per realm |
|---|---|---|
| `woff2` | 500 KB (512,000 bytes) | 8 font files |
| `png`, `webp` | 512 KB | 32 images (svg, png and webp together) |
| `svg` | 256 KB | (same 32) |

- The type comes from the file name's extension and must be **confirmed by the content** (the `wOF2`, PNG or WebP
  signature). The multipart content type is ignored. WOFF 1, TTF, OTF, GIF, JPEG and `svgz` are refused.
- Names are 1–64 characters: letters, digits, spaces, `.`, `_` and `-`, starting with a letter or digit and not
  ending in a space. A font cannot use a built-in stack name.
- A font face (family, weight, style) must be unique in the realm, and one family has **one spelling** per realm:
  uploading `PUBLIC SANS` next to `Public Sans` is refused, naming the existing spelling. One family may have several
  files (for example 400 and 600, or a variable font with weight `100 900`).
- `weight`: 100–900 in steps of 100, or a range such as `100 900`. `style`: `normal` or `italic`. Images take neither.
- Count and duplicate errors are `400` on `fieldErrors.file` / `name`. A request that is not multipart, or has no
  `file` part, is `400`. Bodies over the global 10 MB multipart cap are refused by the container.

**SVG rules.** SVG files are checked and refused, never rewritten. Export **plain SVG or optimised SVG** from your
design tool. Refused:

- a `DOCTYPE` (older Illustrator exports have one), processing instructions (`<?xml-stylesheet?>`), a root other than
  `svg`, UTF-16 or non-UTF-8 input;
- elements outside the SVG allowlist: `script`, `foreignObject`, `image` (embedded or linked raster images),
  `feImage`, `iframe`, XHTML elements, and **editor elements** such as `sodipodi:namedview` (save as "plain" rather
  than "Inkscape SVG"). Editor metadata is allowed only inside `<metadata>` (RDF, Dublin Core, CC, Adobe XMP);
- event attributes (`on…`), `xml:base`, URL-holding attributes such as `ping`, `srcset` or `background`, and any
  `href`/`xlink:href`/`src` that is not a same-document `#id`. **No external references** of any kind;
- `javascript:`, `vbscript:` or `data:` in any attribute;
- in `<style>` elements and `style` attributes: **comments (`/* … */`)**, backslash escapes, `@import`,
  `expression(`, `-moz-binding`, `behavior:`, `image-set(`, `image(`, `cross-fade(`, `src(`, and `url()` other than
  `url(#id)`. XML comments (`<!-- -->`) are fine;
- animations whose `attributeName` is `href`, `style`, `on…` or `xml:base`.

**Deleting an asset that is in use** is refused with `409`, listing every field that refers to it:

```json
{
  "message": "The asset is still used by theme.assets.logoUrl, organizations.3f2a….theme.assets.faviconUrl. Change those fields first.",
  "references": ["theme.assets.logoUrl", "organizations.3f2a….theme.assets.faviconUrl"]
}
```

The check covers the realm layer, every organization layer, and the file theme (`baseTheme.…`): the four asset
fields, the two font fields and custom CSS. A font file can be deleted while another file of the same family
remains, or while the realm's file theme provides that family. An id of another realm is a `404`.

**Serving.** `GET`/`HEAD /realms/{realm}/theme/assets/{id}.{ext}` is public, with:

| Header | Value |
|---|---|
| `Content-Type` | `font/woff2`, `image/svg+xml`, `image/png` or `image/webp` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Disposition` | `inline; filename="{id}.{ext}"`; `attachment` for SVG (an `<img>`, CSS or favicon load ignores it) |
| `ETag` | `"<sha256>"`, and `304` on `If-None-Match` |
| `Cache-Control` | `public, max-age=31536000, immutable` (ids are never reused) |
| `Content-Security-Policy` | SVG: `default-src 'none'; style-src 'unsafe-inline'; sandbox`; others: `default-src 'none'; sandbox` |
| `Cross-Origin-Resource-Policy` | `same-site` for fonts, `cross-origin` for images (email clients) |

No cookie is set. An asset of another realm, a wrong extension or an unknown id is a `404`.

### File theme selection (`theme/base`)

```bash
# Which file theme the realm uses, and every mounted theme with its validation result
curl -s -H "$AUTH" "$HX/admin/realms/acme/theme/base"

# Select one
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"themeName": "acme"}' "$HX/admin/realms/acme/theme/base"

# Clear the selection
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"themeName": null}' "$HX/admin/realms/acme/theme/base"
```

`GET` answers:

```json
{
  "themeName": "acme",
  "status": "active",
  "directory": true,
  "available": [
    {"name": "acme", "valid": true},
    {"name": "broken", "valid": false, "problems": {"theme.json: colors.primary.light": "Colour must be #RRGGBB."}}
  ]
}
```

`status` is `none` (nothing selected), `active`, `refused` (the theme failed validation; the realm uses its database
theme or the default) or `missing` (not mounted). `directory` says whether `helix.theme.directory` is set on the
instance that answered.

`PUT` accepts only `{"themeName": "<name>" | null}`. An unknown field, a bad name, a theme that is not mounted, a
refused theme, or file themes not being enabled is a `400` on `fieldErrors.themeName` (or the unknown field). See
[section 7](#7-file-themes).

### Audit

Every change is audited. Only field names and asset metadata are recorded, never values or bytes.

| Event | When | Detail |
|---|---|---|
| `THEME_UPDATE` | `PUT /theme`, `PUT /theme/base` | `fieldsChanged`, e.g. `colors.primary.light,customCss`, or `themeName` |
| `ORGANIZATION_THEME_UPDATE` | `PUT /organizations/{id}/theme`, `PUT /organizations/{id}/branding` | `fieldsChanged` |
| `THEME_ASSET_UPLOAD` | Asset upload, and each asset stored by an archive import (`source: import`) | `assetId, kind, name, ext, size, sha256` |
| `THEME_ASSET_DELETE` | Asset delete, and a font face replaced by an archive import | same |

```bash
curl -s -H "$AUTH" "$HX/admin/realms/acme/events?type=THEME_UPDATE"
```

The preview is not audited, because it changes nothing.

---

## 4. CSS variables contract (v1)

`/realms/{realm}/theme.css` defines these custom properties. The base stylesheets (`/css/helix.css` on every page,
`/css/login.css` on the sign-in and registration pages) take every colour, font, radius and spacing value from them.
Light values are in `:root`, dark values in `@media (prefers-color-scheme: dark) { :root { … } }`, and `:root` sets
`color-scheme: light dark`.

**Stability.** This is contract **v1**, named in the first line of `theme.css`. Within a major version the variable
names and their meaning do not change and none is removed; new variables may be added in a minor version. A breaking
change bumps the contract version and is listed in the changelog. The **default values** are HelixIAM's own look and
may be adjusted between versions; set the values you depend on in your theme. Variables prefixed `--hxi-` are internal
helpers, not part of the contract.

### Colour roles

From `colors.*`. Dark values are derived when not set.

| Variable | Theme field | Meaning | Default light | Default dark |
|---|---|---|---|---|
| `--hx-primary` | `colors.primary` | Primary buttons, accents, focused field border | `#2f6b52` | `#a7d8c4` |
| `--hx-primary-strong` | `colors.primaryStrong` | Links, card titles, button hover | `#285c46` | `#c4e6d8` |
| `--hx-primary-tint` | `colors.primaryTint` | Secondary buttons, hover tints | `#e6efe9` | `#1f3a2e` |
| `--hx-surface` | `colors.surface` | Page background, header, form panel | `#f6f1e9` | `#141d18` |
| `--hx-surface-raised` | `colors.surfaceRaised` | Cards, input fields | `#ffffff` | `#1b2721` |
| `--hx-surface-sunken` | `colors.surfaceSunken` | Code blocks, recessed areas | `#efe8dc` | `#0f1612` |
| `--hx-ink` | `colors.ink` | Body text, headings | `#22352b` | `#eef0ea` |
| `--hx-ink-muted` | `colors.inkMuted` | Secondary text, placeholders | `#5f6b64` | `#a9b5ad` |
| `--hx-border` | `colors.border` | Borders, hairlines | `#e7ded0` | `#2c3b33` |
| `--hx-negative` | `colors.negative` | Error text and field border | `#9c4b3e` | `#f0a58c` |
| `--hx-negative-tint` | `colors.negativeTint` | Error backgrounds | `#f6e9e5` | `#3a231c` |
| `--hx-positive` | `colors.positive` | Success text | `#2f6b52` | `#8fd4b0` |
| `--hx-positive-tint` | `colors.positiveTint` | Success backgrounds | `#e6efe9` | `#173326` |
| `--hx-focus-ring` | `colors.focusRing` | Keyboard focus ring | `#2f6b52` | `#a7d8c4` |

### Derived colours

These have no model field of their own.

| Variable | Light value | Dark value | Meaning | Default light | Default dark |
|---|---|---|---|---|---|
| `--hx-on-primary` | `surfaceRaised` | `surfaceRaised` | Text and icons on primary (the pair checked for AA) | `#ffffff` | `#1b2721` |
| `--hx-brand-bg` | `ink` | 14 % `primary` in `surfaceSunken` | Brand-panel ground (split layout), card footer bar | `#22352b` | `#24312b` |
| `--hx-brand-fg` | `surface` | `ink` | Text on the brand panel | `#f6f1e9` | `#eef0ea` |
| `--hx-brand-accent` | `primary` (dark value) | `primary` (dark value) | Badges, wordmark accent on the panel; adjusted to 4.5:1 on the panel ground when needed | `#a7d8c4` | `#a7d8c4` |

### Typography and shape

Set once in `:root` (the same in both schemes).

| Variable | Theme field | Meaning | Default |
|---|---|---|---|
| `--hx-font-sans` | `typography.fontSans` | Body text | `"Work Sans", system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif` |
| `--hx-font-display` | `typography.fontDisplay` | Headings, wordmark | as `--hx-font-sans` |
| `--hx-font-display-weight` | from `fontDisplay` | Heading weight | `800` (`helix-sans`); 700 other sans; 600 serif and mono |
| `--hx-font-display-tracking` | from `fontDisplay` | Heading letter-spacing | `-0.02em`; `-0.005em` for serif and mono |
| `--hx-font-mono` | — (fixed) | Recovery codes, secrets | `"Roboto Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace` |
| `--hx-font-size` | `typography.baseSize` | Base size; the root font size is 0.75 × this and text sizes are `rem` | `16px` |
| `--hx-radius` | `shape.radius` | Corner radius | `8px` |
| `--hx-space` | `shape.density` | Spacing unit | `4px` (comfortable), `3px` (compact) |

---

## 5. `theme.css`

Every themed page links the realm's stylesheet:

```html
<link rel="stylesheet" href="/realms/acme/theme.css?v=3c1f0a9b2d4e6f70">
<link rel="stylesheet" href="/realms/acme/theme.css?v=8e21…&org=3f2a…">   <!-- organization in context -->
```

```bash
curl -si "$HX/realms/acme/theme.css"
curl -si "$HX/realms/acme/theme.css?org=$ORG_ID"
```

**Contents**, in this order:

1. a comment naming the contract version;
2. `:root { color-scheme: light dark; --hx-…: <light value>; … }`;
3. `@media (prefers-color-scheme: dark) { :root { --hx-…: <dark value>; … } }` (colours only);
4. one `@font-face` per uploaded font file of a family that `fontSans` or `fontDisplay` names
   (`src: url("/realms/acme/theme/assets/{id}.woff2") format("woff2")`, its weight and style,
   `font-display: swap`);
5. the realm's custom CSS, if it is set and still valid.

**HTTP:**

- `GET` and `HEAD`, public, no cookie set.
- `Content-Type: text/css;charset=utf-8`, `X-Content-Type-Options: nosniff`.
- `ETag: "<sha256 of the stylesheet>"`. It changes when the theme changes, and also when the realm's font files or
  HelixIAM's renderer change. `If-None-Match` answers `304`.
- `Cache-Control: public, max-age=300`.
- `?v=` is a cache buster that the server ignores: pages link the current version (the first 16 hex characters of the
  ETag), so a change reaches browsers at once despite the five-minute `max-age`.
- `?org=<orgId>` selects an organization's theme, but only for an organization of the path realm. Any other value
  (unknown, another realm's, over 128 characters) gets the realm theme, never an error.

**Server-side caching.** The effective theme, the file-theme selection and the rendered stylesheet are each cached for
**30 seconds per replica**. A write clears the cache on the replica that handled it (after the transaction commits);
other replicas pick the change up within 30 seconds.

Every value is checked again when it is printed. A value that does not fit its rule (only possible from a damaged
database row) is replaced by the HelixIAM default.

---

## 6. Custom CSS: the escape hatch

`customCss` is served **inside** `/realms/{realm}/theme.css`, after the variables and fonts. It is never inlined in a
page.

> **Custom CSS depends on HelixIAM's internal page markup and may break across versions.** Class names such as
> `.helix-form`, `.helix-brand` or `.brand-mid` are not part of any contract. Use the theme model and the
> [`--hx-*` variables](#4-css-variables-contract-v1) wherever you can. Every API response that shows a theme with
> custom CSS carries this notice in `notices`.

It is allowed only on the realm layer (and in file themes), never on an organization theme.

**Refused**, each with a message naming the construct:

- more than **32 KB** (UTF-8 bytes);
- any `<` (so no `</style>` breakout);
- **any backslash**: no CSS escapes of any kind;
- **any comment** (`/*`);
- control characters other than tab, line feed, carriage return and form feed;
- `@import`, `@charset`, `@namespace`, `expression(`, `behavior:`, `-moz-binding`, `javascript:`. Keywords are
  matched case-insensitively (ASCII only);
- the other functions that fetch URLs: `image-set(`, `-webkit-image-set(`, `image(`, `cross-fade(`,
  `-webkit-cross-fade(`, `src(`;
- any `url(…)`, quoted or not, whose target is not exactly:
  - one of the realm's own uploaded assets, `/realms/{realm}/theme/assets/{id}.{ext}`, which must exist; or
  - an `https` URL on an origin in the operator allowlist `helix.theme.allowed-image-origins`
    (`HELIX_THEME_ALLOWED_IMAGE_ORIGINS`, comma-separated, exact origin match, empty by default).

  So `data:` URLs, protocol-relative URLs, and origins that only appear elsewhere in the theme (for example the
  logo's host) are refused. `url(` must hold exactly one URL followed by `)`.

Because escapes are refused, **write characters literally**; the stylesheet is UTF-8:

```css
/* refused: */ .quote::before { content: "\201C"; }
/* accepted: */ .quote::before { content: "“"; }
```

(The comments above are for illustration only; comments themselves are refused.)

Example:

```bash
curl -s -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"customCss": ".helix-form h1 { letter-spacing: 0; }"}' \
  "$HX/admin/realms/acme/theme"
```

Remember that `PUT /theme` replaces the whole layer: fetch the stored theme, change `customCss`, and send it all back.

**When stored CSS stops validating** (for example after an upgrade tightens a rule, or a referenced asset is
deleted), it is **not served**: pages render without it and a warning is logged
(`Realm acme: stored custom CSS no longer validates and is not served: …`). It stays stored, and it is flagged:

- `GET`/`PUT /admin/realms/{r}/theme` return the notice `Stored custom CSS is not served because it fails the current
  rules: <reason> Replace or remove it with PUT /admin/realms/{r}/theme.`;
- the realm export carries the same notice in the read-only `themeNotices` field.

The deprecated `customCss` field of `GET /admin/realms/{r}/settings` shows `null` for CSS that is not served. Sending
that `null` back does not delete it; clear it with `PUT /theme`.

---

## 7. File themes

Operators can keep themes in version control and mount them as files. A file theme is validated exactly like an
admin-API theme and becomes the layer between the built-in default and the realm's database theme.

### Directory layout

```
$HELIX_THEME_DIRECTORY/
  acme/
    theme.json       # required: the theme, same schema as PUT /admin/realms/{r}/theme
    fonts.json       # required when assets/ has .woff2 files
    assets/
      logo.svg
      logo-dark.svg
      PublicSans.woff2
```

`theme.json` refers to files as `assets/<file>`, in asset fields and in custom-CSS `url()`s:

```json
{
  "colors": {"primary": {"light": "#1d4ed8"}, "primaryStrong": {"light": "#1e40af"}},
  "typography": {"fontSans": "Public Sans", "fontDisplay": "Public Sans"},
  "assets": {"logoUrl": "assets/logo.svg", "logoDarkUrl": "assets/logo-dark.svg"},
  "texts": {"brandHeadline": "Sign in to Acme", "brandSubhead": "", "brandByline": "", "brandBadges": []}
}
```

`fonts.json` lists every `.woff2` file with its family (the name `typography` uses), weight and style:

```json
[{"file": "PublicSans.woff2", "family": "Public Sans", "weight": "100 900", "style": "normal"}]
```

Rules:

- Theme directory names (what a realm selects): `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Asset file names:
  `[A-Za-z0-9][A-Za-z0-9._-]{0,99}`. Hidden entries are ignored.
- `theme.json` and `fonts.json` are parsed strictly (unknown fields are errors) and may be at most 256 KB.
- Every asset goes through the upload rules (type confirmed by content, size limits, the SVG rules, font names and
  weights) and the per-realm limits (8 fonts, 32 images).
- Files must be regular files inside the themes directory. Symbolic links are followed only while they stay inside
  it, which is how a Kubernetes ConfigMap mount lays files out (`..data`).
- A file asset is served under the selecting realm's own path, `/realms/{realm}/theme/assets/ft-<40 hex>.<ext>`, with
  the same headers as uploads. The id is derived from the theme, the file name and the content, so it changes when the
  file changes (which keeps the year-long caching correct). Another realm's path answers `404`.

### Configuration

| Property | Environment | Default | Meaning |
|---|---|---|---|
| `helix.theme.directory` | `HELIX_THEME_DIRECTORY` | empty (file themes off) | The themes directory |
| `helix.theme.reload-interval-seconds` | `HELIX_THEME_RELOAD_INTERVAL_SECONDS` | `30` | How often the directory is checked for changes; `0` = load at startup only |

Themes are loaded and validated at startup. After that the directory is polled; when a name, size or modification
time changes, every theme is reloaded and the theme caches are cleared.

### Selecting and precedence

A realm selects a theme with `PUT /admin/realms/{r}/theme/base {"themeName": "acme"}` (see
[section 3](#file-theme-selection-themebase)). Several realms may select the same theme. The realm's database theme
and organization themes still apply on top, field by field, so **database fields override file values**. Clear the
realm layer (`PUT /theme {}`) if the file should decide everything.

The selection is cached for about 30 seconds per replica, like the effective theme.

### Invalid themes

A theme with any problem is **refused as a whole** and never used. HelixIAM does not keep an older copy. The server
logs an `ERROR` that names the theme and lists every problem (`theme.json: colors.primary.light`, `assets/logo.svg`,
…); the messages contain no file-system paths. A realm that selects a refused or missing theme falls back to its
database theme or the default, and a `WARN` is logged once per realm per reload. `GET /admin/realms/{r}/theme/base`
shows `status: refused` and the problems. Fix the files and the theme comes back at the next reload.

### Helm

The chart's `themes` value mounts the directory read-only and sets both environment variables:

```yaml
themes:
  enabled: true
  mountPath: /etc/helixiam/themes     # HELIX_THEME_DIRECTORY
  reloadIntervalSeconds: 30
  configMap:
    name: helixiam-themes
    items:                             # ConfigMap keys cannot contain "/", so map them to paths
      - {key: acme.theme.json,       path: acme/theme.json}
      - {key: acme.fonts.json,       path: acme/fonts.json}
      - {key: acme.logo.svg,         path: acme/assets/logo.svg}
      - {key: acme.PublicSans.woff2, path: acme/assets/PublicSans.woff2}
```

```bash
kubectl create configmap helixiam-themes \
  --from-file=acme.theme.json=themes/acme/theme.json \
  --from-file=acme.fonts.json=themes/acme/fonts.json \
  --from-file=acme.logo.svg=themes/acme/assets/logo.svg \
  --from-file=acme.PublicSans.woff2=themes/acme/assets/PublicSans.woff2
```

`kubectl` stores binary files (woff2, png, webp) under `binaryData`. A ConfigMap is limited to 1 MiB in total; for
larger themes, use an existing volume:

```yaml
themes:
  enabled: true
  existingVolume:
    persistentVolumeClaim: {claimName: helixiam-themes, readOnly: true}
```

`existingVolume` takes any volume source and is used when `configMap.name` is empty. Rendering the chart fails when
`themes.enabled` is set without a source.

---

## 8. Content-Security-Policy

With no inline styles left on any page, the page CSP is:

```
default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none';
img-src 'self' data: <realm image origins>; font-src 'self'; style-src 'self';
script-src 'self' <CAPTCHA hosts>; frame-src 'none' | <CAPTCHA frame host>;
connect-src 'self' <CAPTCHA host>; form-action 'self' <registered redirect origins>
```

- **`style-src 'self'`**: no `'unsafe-inline'`. No template has a `<style>` block or a `style=""` attribute; all
  styling comes from `/css/*.css` and `/realms/{realm}/theme.css`.
- **`img-src`** is built per realm and request: `'self' data:`, plus the origins in
  `helix.theme.allowed-image-origins`, plus the `https` origins of the effective theme's own image URLs (logo, dark
  logo, favicon, brand image; the organization's when one is in context), plus the origins of the identity-provider
  button logos. Outside a realm it is `'self' data:`. There is no `https:` wildcard any more.
- **`font-src 'self'`**: fonts load only from HelixIAM (built-in or uploaded).
- **`form-action`**: `'self'` plus the origins of the redirect URIs **registered** for the client of the pending
  authorization request (or the consent page's `client_id`), and on the end-session page the client's post-logout
  redirect origins. Browsers apply `form-action` to the redirects after a form post, so this is what lets
  `POST /login` → `/oauth2/authorize` → `https://app.acme.example/callback` complete. SAML POST-binding pages allow
  `form-action 'self' https:`.
- CAPTCHA hosts are added only when the realm enables Cloudflare Turnstile or Google reCAPTCHA.
- If a lookup fails, the page gets the realm-less policy, never a looser one.

The preview has its own, stricter policy (see [Preview](#preview)). Theme assets have their own (see
[Assets](#assets-upload-list-delete)).

---

## 9. Emails

Verification, password-reset, magic-link and one-time-code emails use the effective theme of the realm, with the
organization in context for that sign-in layered on top:

- **Name:** the organization's display name, else the realm's display name, else HelixIAM. Subjects and texts name
  the realm the same way: `{{realm}}` in a message template is the organization's name, else the realm's display
  name, else (only then) the realm id. `{{realmId}}` is always the id.
- **Logo:** `assets.logoUrl`. An `https` logo is used as is. An uploaded logo is made absolute on `IDP_BASE_URL`
  (`idp.base.url`); without `IDP_BASE_URL` the email has no logo. Many email clients do not display SVG, so a PNG logo
  is the safer choice when you rely on emails.
- **Colours:** the light palette only. Button `primary` with `surfaceRaised` text, background `surface`, card
  `surfaceRaised`, text `ink`, muted text `inkMuted`, borders `border`.
- **Footer:** `texts.footerText` in the user's language, and the `privacyUrl`, `termsUrl` and `supportUrl` links.
- The email is in the user's language. An email sent while handling a request resolves its language like a page
  does, so it is limited to `supportedLocales` too. A realm message template that was not edited (still the English
  default) is sent in Dutch to a Dutch user; an edited template is sent as written.
- Every HTML email has a plain-text part with the same links and codes, for email apps that show only text. Over SMTP
  the email is `multipart/alternative`; the HTTP email driver adds a `text` field to its JSON payload
  (`{from, fromName, to, subject, body, html, contentType, text}`). A link becomes `Label: URL` in the text part.

Branding never blocks a message: if the theme cannot be resolved, the email uses the HelixIAM look.

---

## 10. Import and export

**JSON export and import** (`GET /admin/realms/{r}/export`, `POST /admin/realms/{r}/import`) carry:

| Field | Direction | Contents |
|---|---|---|
| `theme` | export and import | The realm layer (asset references only) |
| `organizationThemes` | export and import | `[{"organization": "<organization name>", "theme": {…}}]` |
| `themeNotices` | export only | Notices such as stored custom CSS that is not served |
| `themeAssets` | export only | Metadata of the uploaded fonts and images (no bytes) |

On import, the `theme` and `organizationThemes` slices are parsed strictly and validated exactly like `PUT /theme`.
A failure is reported in the slice's `failed` entry with the field errors (`422`), and that theme is not stored.
`onConflict` (`overwrite`, the default; `skip`; `fail`) applies as for the other slices. A theme that refers to
uploaded assets validates only where those assets exist, so importing into **another** realm needs the archive.

**Archive export with assets:**

```bash
curl -s -H "$AUTH" -o acme-realm-export.zip "$HX/admin/realms/acme/export?includeAssets=true"

curl -s -X POST -H "$AUTH" -H 'Content-Type: application/zip' \
  --data-binary @acme-realm-export.zip "$HX/admin/realms/acme-staging/import?onConflict=overwrite"
```

The zip holds `realm-export.json`, `theme-assets/manifest.json` (`id, kind, name, ext, weight, style, sha256, size`
per asset) and `theme-assets/{id}.{ext}`.

Import steps:

1. The archive is read defensively. Only the names above are accepted (no `..`, absolute paths, backslashes or
   subfolders), each at most once, at most **64 entries**. Every entry is counted while it is inflated: an asset or
   the manifest at most 512 KB, the document at most 16 MB, **40 MB uncompressed in total**, and at most 40 MB
   compressed. Any problem is a `400 {message, fieldErrors: {archive}}` and nothing is imported.
2. The manifest must match the files one to one, including each file's SHA-256, and may not list a font face twice
   (`400` otherwise).
3. The realm slice runs first, so an archive can create a new realm.
4. Every asset is uploaded again through the normal upload rules and limits, **all or nothing**: if any asset is
   refused, the answer is `422` naming it and nothing is imported. An asset that already exists identically is
   reused, so the same archive can be imported twice.
5. Asset URLs in the realm and organization themes, including custom-CSS `url()`s, are rewritten to the new ids.
   Fonts are referred to by name and need no change.
6. The rest of the document is imported with the usual per-slice behaviour.

`onConflict` for assets. A font "exists" when the target has the same face (family matched case-insensitively,
same weight and style); an image when it has identical content.

| Mode | Identical content | Same font face, other bytes |
|---|---|---|
| `overwrite` (default) | reused (`updated`) | replaced: the old file is deleted and the new one uploaded (`updated`). Refused (`422`) when custom CSS refers to the old file's URL. |
| `skip` | reused (`skipped`) | the existing face is kept (`skipped`) |
| `fail` | as `skip`, plus a conflict `themeAssets:image <name>.<ext>` | as `skip`, plus a conflict `themeAssets:font <Name> <weight> <style>` |

**Undo.** If a later slice of the document fails, the import removes the assets it created and restores the font faces
it replaced, except those that a theme stored by the same import now uses. The document slices keep their per-slice
behaviour (successful slices stay).

Limitations:

- **`themeName` (the file-theme selection) is not exported yet.** Select the file theme again after an import.
- The archive carries uploaded assets only. A database theme that points at a file-theme asset URL does not survive an
  import into another realm (validation refuses it there).
- With `overwrite`, a font whose family the target spells differently (`public sans` against `Public Sans`) is
  refused by the one-spelling rule, and the whole asset stage fails (`422`, nothing imported).

---

## 11. Migrating from 1.0

In 1.0, branding was a few realm settings plus free-form CSS inserted into two pages. The upgrade moves them into the
theme.

**What moves** (Flyway `V19`/`V20`; on the `schema.sql` path the same step runs at startup):

| 1.0 field | Theme field |
|---|---|
| realm `logoUrl` | `assets.logoUrl` |
| realm `primaryColor` | `colors.primary.light` |
| realm `backgroundColor` | `colors.surface.light` |
| realm `welcomeText` | `texts.welcomeText.default` |
| realm `customCss` | `customCss` |
| organization `logoUrl` | organization `assets.logoUrl` |
| organization `primaryColor` | organization `colors.primary.light` |

- Every value is validated on the way. Invalid colours, URLs and texts are dropped, and the log names the realm or
  organization, the field and the reason.
- **Legacy custom CSS is kept only if it passes the new rules** ([section 6](#6-custom-css-the-escape-hatch)). Its
  `url()`s may use the configured `helix.theme.allowed-image-origins` only. Otherwise it is dropped with a warning
  (`…legacy custom CSS dropped during the theme migration and will not be served: …`). CSS that used escapes,
  comments or external images needs rewriting.
- Contrast is not checked on migrated values, but the next `PUT` that touches those colours is checked.
- 1.0's `backgroundColor` recoloured the brand panel. Now it becomes `surface`, the page background; the brand panel
  is derived from `ink` and `primary`.
- CSS written against 1.0 class names or the old `--color-*`, `--kd-*`, `--hx-cucumber` / `--hx-jade` variables will
  mostly not apply any more: `/css/theme.css` and `brand.css` were replaced by `helix.css` and `login.css`, and those
  variables no longer exist. Move to the theme model.

**The old endpoints keep working, deprecated** (marked `deprecated` in the OpenAPI document). They read and write the
theme:

- `GET`/`PUT /admin/realms/{r}/settings`: `logoUrl`, `primaryColor`, `backgroundColor`, `welcomeText`, `customCss`.
  An unchanged value does nothing, invalid values answer `400` under the legacy field name, and `customCss: null` for
  CSS that is not served keeps it.
- `GET`/`PUT /admin/realms/{r}/organizations/{orgId}/branding`: `logoUrl`, `primaryColor`, `displayName`. A missing or
  `null` field is left unchanged; `""` clears it.

They will be removed in a later minor release. Move to `/theme` and `/organizations/{orgId}/theme`.

**The page language now follows `supportedLocales`** (default `["en", "nl"]`). A realm that should offer only one
language must set it, and a realm that offered other languages through browser settings now offers only the listed
ones. This applies to every realm-routed request, including emails sent during a request.

**Rollback.** The migration moves the values and **clears the legacy columns** (`realm_config.logo_url`,
`primary_color`, `background_color`, `welcome_text`, `custom_css`, and `organization.logo_url`, `primary_color`).
The columns are kept but no longer read. Going back to 1.0 therefore shows **no branding**. Take a database backup
before upgrading if you may need to roll back with branding intact.

---

## 12. Known limitations

- **Escapes and comments are refused in custom CSS**, including harmless ones such as `content: "\201C"`. Write the
  character itself (`content: "“"`).
- **Organization texts replace the realm's as a whole map.** An organization that sets `brandHeadline` only in `en`
  shows no realm wording in other languages: it falls back to its own `default`, then to the built-in message. This
  avoids mixing two brands on one page. Give organization texts a `default`.
- **Heading font weight is guessed from the family name** of an uploaded display font (700 for sans, 600 when the
  name suggests serif or mono). There is no field for it yet.
- **The preview covers realm themes only**, and only the sign-in page. There is no organization-theme preview.
- **`schema.sql` path:** with Flyway off (`HELIX_MIGRATIONS_ENABLED=false`), legacy branding is moved at startup by a
  background step, so right after the first start on the new version pages can show the default look for a moment.
- **`themeName` is not exported** in realm export and import.
- **The brand panel has no colour field.** It is derived from `ink`, `surface`, `surfaceSunken` and `primary`.
- **`negative` and `positive` keep HelixIAM's hue** when unset (only their lightness is adjusted for contrast); set
  them if red and green do not suit your brand.
- **Contrast checks** cover the five pairs listed above. An organization layer is not re-checked when the realm's
  colours change later.
- **Identity-provider logo origins** are added to `img-src` from the global provider registry, not only from the
  current realm's providers.
- **Caching:** a theme change can take up to about 30 seconds to reach other replicas.
- **The front-channel logout page** is not themed.
- **SVG input is strict.** Some design-tool exports (DOCTYPE, editor namespaces, embedded images, CSS comments in
  `<style>`) must be re-exported as plain or optimised SVG.

---

## 13. Where the implementation differs from the design spec

The design spec is `docs/superpowers/specs/2026-09-27-structured-theming.md`. The code differs in these places, and
this page documents the code:

- **Links** are a separate `links` group (`links.privacyUrl`, `termsUrl`, `supportUrl`), not part of `texts`.
- **Contrast failures are errors (`400`)**, not warnings. Only pairs the saved layer touches are checked, and three
  more pairs are checked: `contrast.brandPanel.dark` and muted text (`inkMuted`) on `surface` and on `surfaceRaised`.
- **Built-in fonts** also include `helix-sans` (the bundled Work Sans, the default).
- **Custom CSS** is realm-only, and stricter than the spec's list: no escapes, comments or control characters, and no
  `image-set()`, `image()`, `cross-fade()` or `src()`. The `url()` allowlist is the operator setting only; theme asset
  origins do not widen it.
- **`img-src`** also includes the theme's own `https` image origins and the identity-provider logo origins, besides
  the operator allowlist.
- **`theme.css`** starts with a comment naming the contract version and also carries `@font-face` rules and the
  custom CSS, as well as the custom properties.
- **Image limits** are fixed at 512 KB (png, webp) and 256 KB (svg), with 32 images per realm. SVGs are served as
  attachments, and assets also get `Cross-Origin-Resource-Policy`.
- **Deleting a referenced asset** is refused with `409`.
- **There is no `DELETE` for themes**; `PUT {}` clears a layer.
- **Legacy `backgroundColor`** maps to `colors.surface.light`.
- **The preview** renders the sign-in page for realm themes only.
- **The page locale** is limited to `supportedLocales`, and the language switcher is shown only on the sign-in and
  registration pages.
- **Emails** use the light palette only.
- **`themeName` is not part of realm export/import.**
