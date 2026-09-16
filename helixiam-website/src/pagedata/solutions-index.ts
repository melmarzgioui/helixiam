import type { Locale } from "../i18n";
export interface IndexStr { metaTitle: string; metaDesc: string; eyebrow: string; title: string; lead: string; }
export const solutionsIndex: Record<Locale, IndexStr> = {
  en: {
    metaTitle: "Solutions",
    metaDesc: "HelixIAM for developers, security teams, AI & platform teams, and the public sector.",
    eyebrow: "Solutions",
    title: 'Identity that fits <span class="grad-text">your team</span>.',
    lead: "One platform, many jobs to be done. See how HelixIAM maps to what you're trying to ship, secure, or comply with.",
  },
  fr: {
    metaTitle: "Solutions",
    metaDesc: "HelixIAM pour les développeurs, les équipes de sécurité, les équipes IA & plateforme, et le secteur public.",
    eyebrow: "Solutions",
    title: 'Une identité adaptée à <span class="grad-text">votre équipe</span>.',
    lead: "Une plateforme, de nombreuses missions. Découvrez comment HelixIAM répond à ce que vous cherchez à livrer, sécuriser ou mettre en conformité.",
  },
  nl: {
    metaTitle: "Oplossingen",
    metaDesc: "HelixIAM voor ontwikkelaars, securityteams, AI- & platformteams en de overheid.",
    eyebrow: "Oplossingen",
    title: 'Identiteit die past bij <span class="grad-text">jouw team</span>.',
    lead: "Eén platform, veel taken. Ontdek hoe HelixIAM aansluit op wat je wilt bouwen, beveiligen of compliant maken.",
  },
};
