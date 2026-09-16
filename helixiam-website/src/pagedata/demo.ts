import type { Locale } from "../i18n";

export interface DemoPoint { t: string; d: string; i: string; }
export interface DemoStr {
  metaTitle: string;
  metaDesc: string;
  eyebrow: string;
  title: string;
  lead: string;
  altHead: string;
  points: DemoPoint[];
}

export const demo: Record<Locale, DemoStr> = {
  en: {
    metaTitle: "Book a demo",
    metaDesc: "Book a 30-minute HelixIAM demo — tailored to your use case, on a live system.",
    eyebrow: "Book a demo",
    title: 'See HelixIAM on <span class="grad-text">your stack</span>.',
    lead: 'A focused 30 minutes: humans, AI agents, and workloads on one European identity fabric — and a real answer to "how do we get there from here?"',
    altHead: "Prefer to explore first?",
    points: [
      { t: "Mapped to your use case", d: "Migrating off Keycloak, securing AI agents, or adding DigiD — we tailor the session to you.", i: "layers" },
      { t: "A live, running system", d: "Real realms, real tokens, real delegation and workload identity — not slides.", i: "bolt" },
      { t: "Your questions answered", d: "Deployment, sovereignty, pricing, and a realistic migration path.", i: "eye" },
    ],
  },
  fr: {
    metaTitle: "Demander une démo",
    metaDesc: "Réservez une démo HelixIAM de 30 minutes — adaptée à votre cas d'usage, sur un système en direct.",
    eyebrow: "Demander une démo",
    title: 'Découvrez HelixIAM sur <span class="grad-text">votre stack</span>.',
    lead: 'Trente minutes ciblées : humains, agents IA et charges de travail sur une seule trame d\'identité européenne — et une vraie réponse à « comment y arriver depuis notre situation actuelle ? »',
    altHead: "Vous préférez explorer d'abord ?",
    points: [
      { t: "Adapté à votre cas d'usage", d: "Migration depuis Keycloak, sécurisation des agents IA ou ajout de DigiD — nous adaptons la session à vous.", i: "layers" },
      { t: "Un système réel, en fonctionnement", d: "De vrais realms, de vrais jetons, une vraie délégation et identité des charges de travail — pas des diapositives.", i: "bolt" },
      { t: "Vos questions, nos réponses", d: "Déploiement, souveraineté, tarifs et un chemin de migration réaliste.", i: "eye" },
    ],
  },
  nl: {
    metaTitle: "Demo aanvragen",
    metaDesc: "Boek een HelixIAM-demo van 30 minuten — afgestemd op jouw use case, op een live systeem.",
    eyebrow: "Demo aanvragen",
    title: 'Zie HelixIAM op <span class="grad-text">jouw stack</span>.',
    lead: 'Een gerichte 30 minuten: mensen, AI-agents en workloads op één Europese identiteitslaag — en een echt antwoord op "hoe komen we daar vanaf hier?"',
    altHead: "Liever eerst zelf ontdekken?",
    points: [
      { t: "Afgestemd op jouw use case", d: "Migreren van Keycloak, AI-agents beveiligen of DigiD toevoegen — we stemmen de sessie op jou af.", i: "layers" },
      { t: "Een live, draaiend systeem", d: "Echte realms, echte tokens, echte delegatie en workload-identiteit — geen slides.", i: "bolt" },
      { t: "Antwoord op je vragen", d: "Deployment, soevereiniteit, prijzen en een realistisch migratiepad.", i: "eye" },
    ],
  },
};
