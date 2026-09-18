import type { Locale } from "../i18n";

export interface ContactStr {
  metaTitle: string;
  metaDesc: string;
  eyebrow: string;
  title: string;
  lead: string;
  demoSub: string;
  docsSub: string;
  emailLabel: string;
  euNote: string;
}

export const contact: Record<Locale, ContactStr> = {
  en: {
    metaTitle: "Contact",
    metaDesc: "Talk to the HelixIAM team about sovereign identity for humans, AI agents, and workloads.",
    eyebrow: "Contact",
    title: 'Let\'s <span class="grad-text">talk identity</span>.',
    lead: "Questions about deployment, sovereignty, migration, or pricing? Tell us what you're building and we'll point you to the right answer — or the right person.",
    demoSub: "See it live in 30 minutes.",
    docsSub: "Quickstarts & API reference.",
    emailLabel: "Email us",
    euNote: "HelixIAM is engineered in Europe.",
  },
  fr: {
    metaTitle: "Contact",
    metaDesc: "Parlez à l'équipe HelixIAM de l'identité souveraine pour les humains, les agents IA et les charges de travail.",
    eyebrow: "Contact",
    title: 'Parlons <span class="grad-text">identité</span>.',
    lead: "Des questions sur le déploiement, la souveraineté, la migration ou les tarifs ? Dites-nous ce que vous construisez et nous vous orienterons vers la bonne réponse — ou la bonne personne.",
    demoSub: "Voyez-le en direct en 30 minutes.",
    docsSub: "Guides de démarrage & référence API.",
    emailLabel: "Écrivez-nous",
    euNote: "HelixIAM est conçu en Europe.",
  },
  nl: {
    metaTitle: "Contact",
    metaDesc: "Praat met het HelixIAM-team over soevereine identiteit voor mensen, AI-agents en workloads.",
    eyebrow: "Contact",
    title: 'Laten we het over <span class="grad-text">identiteit</span> hebben.',
    lead: "Vragen over deployment, soevereiniteit, migratie of prijzen? Vertel ons wat je bouwt en we wijzen je naar het juiste antwoord — of de juiste persoon.",
    demoSub: "Zie het live in 30 minuten.",
    docsSub: "Quickstarts & API-referentie.",
    emailLabel: "Mail ons",
    euNote: "HelixIAM is ontwikkeld in Europa.",
  },
};
