import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";

// helixiam.com — static marketing site. Canonical site URL drives canonical tags + the
// manual /sitemap.xml endpoint (src/pages/sitemap.xml.ts).
export default defineConfig({
  site: "https://helixiam.com",
  integrations: [mdx()],
  // Path-based i18n: English at root, French at /fr, Dutch at /nl. Great for SEO (distinct
  // indexable URLs) + hreflang. English is the default and keeps clean root URLs.
  i18n: {
    defaultLocale: "en",
    locales: ["en", "fr", "nl"],
    routing: { prefixDefaultLocale: false },
  },
  build: { inlineStylesheets: "auto" },
  server: { port: 4330, host: true },
});
