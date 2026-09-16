import type { Locale } from "../i18n";

export interface ValueCard {
  t: string;
  d: string;
  i: string;
}

export interface CompanyStr {
  metaTitle: string;
  metaDesc: string;
  eyebrow: string;
  title: string;
  lead: string;
  leadP1: string;
  leadP2: string;
  leadP3: string;
  values: ValueCard[];
  ctaTitle: string;
  ctaSub: string;
}

export const company: Record<Locale, CompanyStr> = {
  en: {
    metaTitle: "About",
    metaDesc:
      "HelixIAM is the European identity fabric for humans, AI agents and workloads — a KubeDNA product, engineered in Europe.",
    eyebrow: "About HelixIAM",
    title: 'Identity infrastructure for the <span class="grad-text">next decade</span>.',
    lead: "HelixIAM is a KubeDNA product. We're building the identity fabric that authenticates everyone and everything — people, AI agents, and machine workloads — on open standards, with European sovereignty at its core.",
    leadP1:
      "Most identity platforms were designed for a world of humans logging into apps. That world is gone. Today, a single request can pass through a user, an AI agent acting on their behalf, and a fleet of workloads — each needing an identity, each needing to be governed and revoked.",
    leadP2:
      "<strong>HelixIAM treats them as one system.</strong> Human identity and non-human identity are the two strands of the same helix: issued the same way, delegated the same way, audited the same way, and shut off the same way. It's Keycloak-class for everything you do today, and built for everything you're about to.",
    leadP3:
      'We\'re part of <a href="https://kubedna.com" target="_blank" rel="noopener">KubeDNA</a> and engineered in Europe — because we believe the systems that decide who gets in should answer to you, not to a control plane on another continent.',
    values: [
      { t: "Open by default", d: "We build on public standards — OIDC, SAML, WebAuthn, FAPI, RFC 8693. No proprietary lock-in, ever.", i: "protocol" },
      { t: "Sovereign by design", d: "Identity is critical infrastructure. It should run where you do, under keys you hold, on your continent.", i: "eu" },
      { t: "Ready for what's next", d: "AI agents and autonomous workloads are identities too. We build the layer they'll need before they need it.", i: "agent" },
      { t: "Boringly reliable", d: "Auth is not where you want surprises. We obsess over correctness, migrations, and zero-downtime.", i: "shield" },
    ],
    ctaTitle: "Build on identity you control.",
    ctaSub:
      "See how HelixIAM fits your architecture, your compliance needs, and your roadmap — on a live system.",
  },
  fr: {
    metaTitle: "À propos",
    metaDesc:
      "HelixIAM est la plateforme d'identité européenne pour les humains, les agents IA et les charges de travail — un produit KubeDNA, conçu en Europe.",
    eyebrow: "À propos de HelixIAM",
    title: 'Une infrastructure d\'identité pour la <span class="grad-text">prochaine décennie</span>.',
    lead: "HelixIAM est un produit KubeDNA. Nous construisons la plateforme d'identité qui authentifie tout le monde et tout — les personnes, les agents IA et les charges de travail — sur des standards ouverts, avec la souveraineté européenne en son cœur.",
    leadP1:
      "La plupart des plateformes d'identité ont été conçues pour un monde d'humains se connectant à des applications. Ce monde n'existe plus. Aujourd'hui, une seule requête peut traverser un utilisateur, un agent IA agissant en son nom et une flotte de charges de travail — chacun ayant besoin d'une identité, chacun devant être gouverné et révoqué.",
    leadP2:
      "<strong>HelixIAM les traite comme un seul système.</strong> L'identité humaine et l'identité non humaine sont les deux brins de la même hélice : émises de la même manière, déléguées de la même manière, auditées de la même manière et coupées de la même manière. De classe Keycloak pour tout ce que vous faites aujourd'hui, et conçu pour tout ce que vous êtes sur le point de faire.",
    leadP3:
      'Nous faisons partie de <a href="https://kubedna.com" target="_blank" rel="noopener">KubeDNA</a> et sommes conçus en Europe — parce que nous croyons que les systèmes qui décident qui entre devraient vous répondre à vous, et non à un plan de contrôle situé sur un autre continent.',
    values: [
      { t: "Ouvert par défaut", d: "Nous construisons sur des standards publics — OIDC, SAML, WebAuthn, FAPI, RFC 8693. Aucun verrouillage propriétaire, jamais.", i: "protocol" },
      { t: "Souverain par conception", d: "L'identité est une infrastructure critique. Elle doit s'exécuter là où vous êtes, sous des clés que vous détenez, sur votre continent.", i: "eu" },
      { t: "Prêt pour la suite", d: "Les agents IA et les charges de travail autonomes sont aussi des identités. Nous construisons la couche dont ils auront besoin avant qu'ils n'en aient besoin.", i: "agent" },
      { t: "D'une fiabilité ennuyeuse", d: "L'authentification n'est pas l'endroit où vous voulez des surprises. Nous sommes obsédés par l'exactitude, les migrations et le zéro temps d'arrêt.", i: "shield" },
    ],
    ctaTitle: "Bâtissez sur une identité que vous contrôlez.",
    ctaSub:
      "Découvrez comment HelixIAM s'adapte à votre architecture, à vos besoins de conformité et à votre feuille de route — sur un système en direct.",
  },
  nl: {
    metaTitle: "Over ons",
    metaDesc:
      "HelixIAM is de Europese identiteitslaag voor mensen, AI-agents en workloads — een KubeDNA-product, ontwikkeld in Europa.",
    eyebrow: "Over HelixIAM",
    title: 'Identiteitsinfrastructuur voor het <span class="grad-text">komende decennium</span>.',
    lead: "HelixIAM is een KubeDNA-product. We bouwen de identiteitslaag die iedereen en alles authenticeert — mensen, AI-agents en machine-workloads — op open standaarden, met Europese soevereiniteit als kern.",
    leadP1:
      "De meeste identiteitsplatformen zijn ontworpen voor een wereld van mensen die op apps inloggen. Die wereld is verdwenen. Vandaag kan één enkele aanvraag door een gebruiker, een AI-agent die namens hem handelt en een vloot workloads gaan — elk met behoefte aan een identiteit, elk om beheerd en ingetrokken te worden.",
    leadP2:
      "<strong>HelixIAM behandelt ze als één systeem.</strong> Menselijke identiteit en non-human identity zijn de twee strengen van dezelfde helix: op dezelfde manier uitgegeven, gedelegeerd, geaudit en afgesloten. Van Keycloak-niveau voor alles wat je vandaag doet, en gebouwd voor alles wat je op het punt staat te doen.",
    leadP3:
      'We maken deel uit van <a href="https://kubedna.com" target="_blank" rel="noopener">KubeDNA</a> en zijn ontwikkeld in Europa — omdat we geloven dat de systemen die bepalen wie er binnenkomt aan jou verantwoording moeten afleggen, niet aan een control plane op een ander continent.',
    values: [
      { t: "Open van standaard", d: "We bouwen op publieke standaarden — OIDC, SAML, WebAuthn, FAPI, RFC 8693. Nooit propriëtaire lock-in.", i: "protocol" },
      { t: "Soeverein van opzet", d: "Identiteit is kritieke infrastructuur. Het hoort te draaien waar jij draait, onder sleutels die jij beheert, op jouw continent.", i: "eu" },
      { t: "Klaar voor wat komt", d: "AI-agents en autonome workloads zijn ook identiteiten. We bouwen de laag die ze nodig hebben voordat ze die nodig hebben.", i: "agent" },
      { t: "Saai betrouwbaar", d: "Auth is niet de plek waar je verrassingen wilt. We zijn geobsedeerd door correctheid, migraties en zero-downtime.", i: "shield" },
    ],
    ctaTitle: "Bouw op identiteit die jij beheert.",
    ctaSub:
      "Zie hoe HelixIAM past bij je architectuur, je compliance-eisen en je roadmap — op een live systeem.",
  },
};
