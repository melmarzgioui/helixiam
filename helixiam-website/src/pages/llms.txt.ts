import type { APIRoute } from "astro";
import { SITE } from "../consts";
import { FEATURES } from "../data/product";
import { SOLUTIONS } from "../data/solutions";

// llms.txt — a curated, machine-readable map of the site for LLMs and AI crawlers.
// Spec: https://llmstxt.org/  · Kept in sync with the nav + data files.
const u = (p: string) => new URL(p, SITE.url).href;
const plain = (s: string) => s.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();

export const GET: APIRoute = () => {
  const body = `# ${SITE.name}

> ${SITE.description}

${SITE.name} (${SITE.tagline}) is a European, standards-based identity
platform (IAM) that authenticates humans, AI agents, and machine workloads on one open fabric.
Keycloak-class SSO, MFA, and federation, plus first-class non-human identity (AI agents, RFC 8693
delegation), Workload Identity Federation, and EU eIDs (eIDAS, eHerkenning, DigiD). Self-hostable and
sovereign by design. Languages: English (default, ${u("/")}), French (${u("/fr/")}), Dutch (${u("/nl/")}).

## Product
- [Platform overview](${u("/product/")}): One identity fabric for humans, AI agents, and workloads.
${FEATURES.map((f) => `- [${f.navLabel}](${u(`/product/${f.slug}/`)}): ${plain(f.metaDesc)}`).join("\n")}

## Solutions
${SOLUTIONS.map((s) => `- [${s.navLabel}](${u(`/solutions/${s.slug}/`)}): ${plain(s.metaDesc)}`).join("\n")}

## Company
- [Why ${SITE.name}](${u("/why-helixiam/")}): Why teams switch — built for agents, sovereign, standards-based.
- [About](${u("/company/")}): European identity, engineered in Europe.
- [Trust & security](${u("/trust/")}): How ${SITE.name} protects identity.
- [Blog](${u("/blog/")}): Notes on the identity fabric.
- [Contact](${u("/contact/")}) · [Book a demo](${u("/demo/")})

## Documentation
- [Docs](${SITE.docsUrl}): Guides, API reference, SDK, and Terraform provider.

## Contact
- Email: ${SITE.email}
`;
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
};
