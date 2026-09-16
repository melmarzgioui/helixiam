import type { Locale } from "../i18n";

export interface NotFoundStr {
  metaTitle: string;
  eyebrow: string;
  title: string;
  lead: string;
}

export const notfound: Record<Locale, NotFoundStr> = {
  en: {
    metaTitle: "Page not found",
    eyebrow: "404",
    title: 'This strand <span class="grad-text">doesn\'t exist</span>.',
    lead: "The page you're after isn't here — it may have moved. Let's get you back on track.",
  },
  fr: {
    metaTitle: "Page introuvable",
    eyebrow: "404",
    title: 'Ce brin <span class="grad-text">n\'existe pas</span>.',
    lead: "La page que vous cherchez n'est pas ici — elle a peut-être été déplacée. Remettons-vous sur la bonne voie.",
  },
  nl: {
    metaTitle: "Pagina niet gevonden",
    eyebrow: "404",
    title: 'Deze streng <span class="grad-text">bestaat niet</span>.',
    lead: "De pagina die je zoekt is hier niet — mogelijk is die verplaatst. Laten we je weer op weg helpen.",
  },
};
