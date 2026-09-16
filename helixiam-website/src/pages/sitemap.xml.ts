import type { APIRoute } from "astro";
import { SITE } from "../consts";
import { FEATURES } from "../data/product";
import { SOLUTIONS } from "../data/solutions";
import { LOCALES, LOCALE_META, localizePath, DEFAULT_LOCALE } from "../i18n";

// Every canonical (English) path. The whole site is translated, so each gets one <url> per locale
// with the full hreflang alternate set. Docs live on docs.helixiam.com; 404 is excluded.
const canonicalPaths = [
  "/", "/product/", "/solutions/", "/why-helixiam/", "/company/", "/trust/",
  "/blog/", "/contact/", "/demo/", "/legal/privacy/", "/legal/terms/",
  ...FEATURES.map((f) => `/product/${f.slug}/`),
  ...SOLUTIONS.map((s) => `/solutions/${s.slug}/`),
];

const abs = (p: string) => new URL(p, SITE.url).href;

function localizedEntry(canonicalPath: string, locale: (typeof LOCALES)[number]): string {
  const links = LOCALES.map(
    (l) => `    <xhtml:link rel="alternate" hreflang="${LOCALE_META[l].htmlLang}" href="${abs(localizePath(canonicalPath, l))}"/>`
  ).join("\n");
  const xdefault = `    <xhtml:link rel="alternate" hreflang="x-default" href="${abs(localizePath(canonicalPath, DEFAULT_LOCALE))}"/>`;
  return `  <url>
    <loc>${abs(localizePath(canonicalPath, locale))}</loc>
    <changefreq>weekly</changefreq>
${links}
${xdefault}
  </url>`;
}

export const GET: APIRoute = () => {
  const urls = canonicalPaths.flatMap((p) => LOCALES.map((l) => localizedEntry(p, l)));
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
${urls.join("\n")}
</urlset>`;
  return new Response(body, { headers: { "Content-Type": "application/xml" } });
};
