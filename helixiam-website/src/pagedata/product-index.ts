import type { Locale } from "../i18n";
export interface IndexStr { metaTitle: string; metaDesc: string; eyebrow: string; title: string; lead: string; }
export const productIndex: Record<Locale, IndexStr> = {
  en: {
    metaTitle: "Platform",
    metaDesc: "One identity fabric for humans, AI agents and workloads — authentication, SSO & federation, non-human identity, European eIDs, developer tooling and security.",
    eyebrow: "The platform",
    title: 'One fabric for <span class="grad-text">every identity</span>.',
    lead: "HelixIAM is a complete, Keycloak-class identity platform — and the only one that treats humans, AI agents, and workloads as first-class citizens of the same system. Explore the eight pillars.",
  },
  fr: {
    metaTitle: "Plateforme",
    metaDesc: "Une seule trame d'identité pour les humains, les agents IA et les charges de travail — authentification, SSO & fédération, identité non humaine, eID européens, outils pour développeurs et sécurité.",
    eyebrow: "La plateforme",
    title: 'Une seule trame pour <span class="grad-text">chaque identité</span>.',
    lead: "HelixIAM est une plateforme d'identité complète, de classe Keycloak — et la seule qui traite les humains, les agents IA et les charges de travail comme des citoyens de premier plan du même système. Découvrez les huit piliers.",
  },
  nl: {
    metaTitle: "Platform",
    metaDesc: "Eén identiteitslaag voor mensen, AI-agents en workloads — authenticatie, SSO & federatie, non-human identity, Europese eID's, ontwikkelaarstools en beveiliging.",
    eyebrow: "Het platform",
    title: 'Eén laag voor <span class="grad-text">elke identiteit</span>.',
    lead: "HelixIAM is een compleet identiteitsplatform van Keycloak-niveau — en het enige dat mensen, AI-agents en workloads behandelt als eersteklas burgers van hetzelfde systeem. Ontdek de acht pijlers.",
  },
};
