import type { Locale } from "../i18n";

export interface BlogPost { t: string; d: string; tag: string; }
export interface BlogStr {
  metaTitle: string;
  metaDesc: string;
  eyebrow: string;
  title: string;
  lead: string;
  chip: string;
  whatNext: string;
  soon: string;
  docsLine: string;
  planned: BlogPost[];
}

export const blog: Record<Locale, BlogStr> = {
  en: {
    metaTitle: "Blog",
    metaDesc: "Notes on the identity fabric — non-human identity, standards, sovereignty and migration from the HelixIAM team.",
    eyebrow: "Blog",
    title: 'Notes on the <span class="grad-text">identity fabric</span>.',
    lead: "Deep dives on non-human identity, open standards, European sovereignty, and getting off legacy IAM. First posts landing soon.",
    chip: "Coming soon",
    whatNext: "What we're writing next",
    soon: "Coming soon",
    docsLine: "In the meantime, the documentation is the deepest source of truth.",
    planned: [
      { t: "Why non-human identity needs a first-class home", d: "AI agents and workloads are exploding in number. Here's why bolting them onto human IAM breaks down — and what a real model looks like.", tag: "Non-human identity" },
      { t: "On-behalf-of, explained", d: "A practical walkthrough of RFC 8693 token exchange: how an agent can act for a user without becoming the user.", tag: "Standards" },
      { t: "Sovereign identity in Europe", d: "What eIDAS 2.0, DigiD and data residency mean for the systems that decide who gets in.", tag: "Sovereignty" },
      { t: "Migrating off Keycloak without the big bang", d: "Import realms, run side by side, cut over app by app. A field guide.", tag: "Migration" },
    ],
  },
  fr: {
    metaTitle: "Blog",
    metaDesc: "Réflexions sur la trame d'identité — identité non humaine, standards, souveraineté et migration, par l'équipe HelixIAM.",
    eyebrow: "Blog",
    title: 'Réflexions sur la <span class="grad-text">trame d\'identité</span>.',
    lead: "Analyses approfondies sur l'identité non humaine, les standards ouverts, la souveraineté européenne et la migration depuis l'IAM historique. Premiers articles bientôt.",
    chip: "Bientôt disponible",
    whatNext: "Nos prochains articles",
    soon: "Bientôt disponible",
    docsLine: "En attendant, la documentation est la source de vérité la plus complète.",
    planned: [
      { t: "Pourquoi l'identité non humaine mérite une vraie place", d: "Le nombre d'agents IA et de charges de travail explose. Voici pourquoi les greffer sur l'IAM humaine ne tient pas — et à quoi ressemble un vrai modèle.", tag: "Identité non humaine" },
      { t: "« Au nom de », expliqué", d: "Un guide pratique de l'échange de jetons RFC 8693 : comment un agent peut agir pour un utilisateur sans devenir cet utilisateur.", tag: "Standards" },
      { t: "L'identité souveraine en Europe", d: "Ce que eIDAS 2.0, DigiD et la résidence des données signifient pour les systèmes qui décident qui entre.", tag: "Souveraineté" },
      { t: "Migrer depuis Keycloak sans big bang", d: "Importez les realms, faites tourner en parallèle, basculez application par application. Un guide de terrain.", tag: "Migration" },
    ],
  },
  nl: {
    metaTitle: "Blog",
    metaDesc: "Aantekeningen over de identiteitslaag — non-human identity, standaarden, soevereiniteit en migratie, van het HelixIAM-team.",
    eyebrow: "Blog",
    title: 'Aantekeningen over de <span class="grad-text">identiteitslaag</span>.',
    lead: "Diepgaande analyses over non-human identity, open standaarden, Europese soevereiniteit en het verlaten van legacy-IAM. Eerste artikelen binnenkort.",
    chip: "Binnenkort beschikbaar",
    whatNext: "Wat we hierna schrijven",
    soon: "Binnenkort beschikbaar",
    docsLine: "Ondertussen is de documentatie de meest volledige bron van waarheid.",
    planned: [
      { t: "Waarom non-human identity een eersteklas plek verdient", d: "Het aantal AI-agents en workloads explodeert. Dit is waarom ze vastplakken op menselijke IAM misgaat — en hoe een echt model eruitziet.", tag: "Non-human identity" },
      { t: "'Namens', uitgelegd", d: "Een praktische uitleg van RFC 8693-token-exchange: hoe een agent namens een gebruiker kan handelen zonder die gebruiker te worden.", tag: "Standaarden" },
      { t: "Soevereine identiteit in Europa", d: "Wat eIDAS 2.0, DigiD en dataresidentie betekenen voor de systemen die bepalen wie binnenkomt.", tag: "Soevereiniteit" },
      { t: "Migreren van Keycloak zonder big bang", d: "Importeer realms, draai parallel, stap app voor app over. Een praktijkgids.", tag: "Migratie" },
    ],
  },
};
