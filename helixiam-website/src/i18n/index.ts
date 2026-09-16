// i18n core: locales, path helpers, hreflang alternates, and translated strings (chrome + home).
// English is the default (root URLs); French → /fr, Dutch → /nl.

export const LOCALES = ["en", "fr", "nl"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

export const LOCALE_META: Record<Locale, { label: string; short: string; htmlLang: string; ogLocale: string }> = {
  en: { label: "English", short: "EN", htmlLang: "en", ogLocale: "en_US" },
  fr: { label: "Français", short: "FR", htmlLang: "fr", ogLocale: "fr_FR" },
  nl: { label: "Nederlands", short: "NL", htmlLang: "nl", ogLocale: "nl_NL" },
};

/** Prefix an app-absolute path (e.g. "/product/") for a locale. English stays unprefixed. */
export function localizePath(path: string, locale: Locale): string {
  const clean = path.startsWith("/") ? path : `/${path}`;
  if (locale === DEFAULT_LOCALE) return clean;
  return clean === "/" ? `/${locale}/` : `/${locale}${clean}`;
}

/** Detect the active locale from a pathname. */
export function localeOf(pathname: string): Locale {
  const seg = pathname.split("/").filter(Boolean)[0];
  return (LOCALES as readonly string[]).includes(seg as Locale) ? (seg as Locale) : DEFAULT_LOCALE;
}

/** Strip the locale prefix back to the canonical (English) path. */
export function unlocalize(pathname: string): string {
  const loc = localeOf(pathname);
  if (loc === DEFAULT_LOCALE) return pathname || "/";
  const stripped = pathname.replace(new RegExp(`^/${loc}`), "");
  return stripped === "" ? "/" : stripped;
}

/** External docs URL, localized where the docs site supports it (root falls back to EN). */
export const docsUrl = (locale: Locale) => (locale === "en" ? "https://docs.helixiam.com" : `https://docs.helixiam.com/${locale}/`);

export const t = (locale: Locale) => STR[locale] ?? STR.en;

// ---- Chrome + home strings ---------------------------------------------------------------

type Dict = typeof STR.en;

const en = {
  tagline: "Identity, in your DNA.",
  meta: {
    home: "HelixIAM is the European identity platform for the agentic enterprise — authenticate, authorize, and govern humans, AI agents, and workloads from one platform. Keycloak-class SSO, MFA, and federation, purpose-built non-human and workload identity, and EU eIDs. A KubeDNA product.",
  },
  nav: {
    product: "Product", solutions: "Solutions", why: "Why HelixIAM", docs: "Docs", company: "Company",
    contact: "Contact", demo: "Book a demo",
    // product children
    platform: "Platform overview", auth: "Authentication & MFA", sso: "SSO & Federation",
    agents: "AI Agents & NHI", workload: "Workload Identity", eid: "European eIDs",
    developers: "Developer experience", security: "Security & Compliance",
    // solutions children
    forDevs: "For developers", forSec: "For security & CISOs", forAi: "For AI & platform teams", forGov: "Public sector & regulated",
    // company children
    about: "About", trust: "Trust & security", blog: "Blog",
  },
  cta: { book: "Book a demo", docs: "Read the docs", explore: "Explore the platform", learn: "Learn more", fine: "No credit card. Self-hostable. Engineered in Europe.", bandTitle: "See HelixIAM on your own stack.", bandSub: "A 30-minute demo: realms, agents, workload identity, and a live migration off Keycloak — mapped to your use case." },
  footer: { tag: "The European identity fabric for humans, AI agents, and workloads.", sovereign: "Sovereign by design", standards: "Open standards", product: "Product", solutions: "Solutions", developers: "Developers", company: "Company", rights: "A KubeDNA product. Engineered in Europe.", privacy: "Privacy", terms: "Terms", security: "Security" },
  langLabel: "Language",
  ui: {
    explore: "Explore", view: "View", exploreMore: "Explore more of the platform",
    seeTheFit: "See the fit", relevantCapabilities: "Relevant capabilities",
    featureComplete: "Feature complete", everythingShipped: "Everything, shipped and documented.",
    comingSoon: "Coming soon", whatNext: "What we're writing next",
    docsDeepest: "In the meantime, the documentation is the deepest source of truth.",
    backHome: "Back to home", explorePlatform: "Explore the platform", notFoundEyebrow: "404",
    legalEyebrow: "Legal", legalUpdated: "Last updated:",
    legalNote: "This is a template intended to be reviewed and completed by HelixIAM / KubeDNA's legal counsel before publication. Placeholders in [brackets] must be replaced with the operating legal entity's details.",
  },
  form: {
    name: "Full name", email: "Work email", company: "Company", role: "Your role",
    roleSelect: "Select…", roleDev: "Developer / Engineer", roleSec: "Security / CISO",
    roleAi: "AI / Platform", roleProduct: "Product / Leadership", rolePublic: "Public sector", roleOther: "Other",
    msgDemo: "What would you like to see?", msgContact: "How can we help?",
    phDemo: "e.g. migrating off Keycloak, AI-agent identity, DigiD…", phContact: "Tell us a bit about your use case.",
    consentPre: "I agree to be contacted about HelixIAM and accept the ", privacyPolicy: "privacy policy", consentPost: ".",
    submitDemo: "Request my demo", submitContact: "Send message",
    fine: "We reply within one business day. No spam, ever.",
    errName: "Please enter your name.", errEmail: "Please enter a valid work email.",
    errCompany: "Please enter your company.", errMessage: "Please add a short message.",
    errConsent: "Please accept the privacy policy to continue.",
    successTitle: "Thank you — you're in the queue.",
    successPre: "We've received your request and someone from the team will reach out within one business day. In the meantime, the ",
    documentation: "documentation", successPost: " is a great place to explore.",
  },
  home: {
    eyebrow: "Identity for humans · AI agents · workloads",
    h1a: "Identity, in your ", h1b: "DNA", h1c: ".",
    lead: "HelixIAM is the identity platform for the agentic enterprise. Authenticate, authorize, and govern <strong>every identity — human and non-human</strong>: your people, their AI agents, and the workloads acting on their behalf. Keycloak-class SSO, MFA, and federation, purpose-built agent and workload identity, and EU data sovereignty — from one platform.",
    trust: ["Open standards — OIDC, SAML, FAPI, WebAuthn. No lock-in.", "EU-sovereign & self-hostable", "Purpose-built for AI-agent & workload identity"],
    humanLabel: "Human identity", nhLabel: "Agents & workloads",
    logos: "Built for the teams securing modern software — from scale-ups to the public sector",
    logoSlots: ["Your platform", "Your bank", "Your SaaS", "Your agency", "Your ministry"],
    strandsEyebrow: "One fabric, two strands",
    strandsTitleA: "Every identity your systems touch — ", strandsTitleB: "on one platform",
    strandsLead: "Most IAM was built for humans and had machines bolted on later. HelixIAM treats human and non-human identity as the two strands of the same helix — issued, governed, and revoked the same way.",
    strands: [
      { title: "Human identity", blurb: "Passwordless passkeys, adaptive MFA, SSO and federation for every person — employees, customers, and citizens.", points: ["Passkeys & WebAuthn", "Adaptive, risk-based MFA", "OIDC · SAML · social · LDAP", "EU eIDs out of the box"] },
      { title: "Non-human identity", blurb: "First-class identity for AI agents and workloads — scoped tokens, on-behalf-of delegation, and keyless federation.", points: ["AI-agent identities", "RFC 8693 delegation (act-as)", "Workload Identity Federation", "Attenuated, kill-switchable"] },
    ],
    whyEyebrow: "Why HelixIAM", whyTitle: "Four reasons teams switch.",
    diff: [
      { title: "Built for AI agents & workloads", blurb: "Not bolted on. HelixIAM treats AI agents and machine workloads as first-class subjects — with delegation, attenuation, and governance most IAMs simply don't have." },
      { title: "Sovereign & European", blurb: "Your realm, your keys, your continent. Self-hostable, per-realm signing keys, EU data residency, and DigiD / eHerkenning / eIDAS built in — not a plugin." },
      { title: "Standards to the core", blurb: "OAuth 2.1, OIDC, SAML 2.0, WebAuthn, FAPI, DPoP, RFC 8693 & RFC 8628. Open protocols, zero lock-in, and a clean migration path off Keycloak." },
      { title: "An afternoon, not a quarter", blurb: "A polished admin console, SDKs, a Terraform provider, and full config-as-code. Realms, clients, and flows are versioned like the rest of your stack." },
    ],
    agentChip: "New — Non-Human Identity",
    agentTitleA: "Give your ", agentTitleB: "AI agents", agentTitleC: " a real identity.",
    agentLead: "Agents act on behalf of users and call tools autonomously. HelixIAM issues each agent its own identity, mints <strong>on-behalf-of</strong> tokens (RFC 8693) that carry the user <em>and</em> the agent, and lets you attenuate scope, require consent, and pull a kill-switch — instantly.",
    agentPoints: ["Agent registry & lifecycle", "Delegation with intersected scope", "Workload Identity Federation (keyless)", "MCP-ready OAuth 2.1 auth"],
    agentCta1: "Explore agent identity", agentCta2: "Workload identity",
    capEyebrow: "The whole platform",
    capTitleA: "Everything a modern IAM needs — ", capTitleB: "and the next thing too",
    capLead: "A complete, Keycloak-class feature set. All shipped. All documented.",
    easeEyebrow: "Easy on purpose", easeTitle: "From zero to secure login in an afternoon.",
    ease: [
      { t: "Spin up a realm", d: "One container or a Helm chart. Import your Keycloak realm, or start fresh — every setting is config-as-code." },
      { t: "Add your app", d: "Register an OIDC or SAML client in the console, or declare it in Terraform. Passkeys and MFA are on by default." },
      { t: "Ship & govern", d: "Wire the SDK, go live, and watch every human, agent, and workload in one audited, revocable place." },
    ],
    codeComment: "// Passwordless in three lines — the SDK handles PKCE, passkeys & refresh.",
    codeComment2: "// passkey / MFA / SSO — your flow, your rules",
    euEyebrow: "Sovereign by design",
    euTitleA: "Your realm. Your keys. ", euTitleB: "Your continent.",
    euLead: "HelixIAM runs where you do — your cloud, your data centre, air-gapped if you need it. Per-realm signing keys never leave your control, and Europe's eIDs are first-class, not a plugin.",
    euPoints: ["EU data residency & self-hosting", "Per-realm KMS keys + rotation", "DigiD · eHerkenning · eIDAS built in", "GDPR rights tooling included"],
    euCta: "European eIDs & sovereignty",
    stats: [
      { value: "3", label: "identity subjects", sub: "humans · agents · workloads" },
      { value: "9", label: "auth factors", sub: "passkeys to device push" },
      { value: "100%", label: "open standards", sub: "no proprietary lock-in" },
      { value: "EU", label: "sovereign by design", sub: "your keys, your realm" },
    ],
  },
};

const fr: typeof en = {
  tagline: "L'identité, dans votre ADN.",
  meta: {
    home: "HelixIAM est la plateforme d'identité européenne pour l'entreprise à l'ère des agents IA — authentifiez, autorisez et gouvernez les humains, les agents IA et les charges de travail depuis une seule plateforme. SSO, MFA et fédération de classe Keycloak, identité non humaine et des charges de travail conçue sur mesure, et eID de l'UE. Un produit KubeDNA.",
  },
  nav: {
    product: "Produit", solutions: "Solutions", why: "Pourquoi HelixIAM", docs: "Docs", company: "Entreprise",
    contact: "Contact", demo: "Demander une démo",
    platform: "Aperçu de la plateforme", auth: "Authentification & MFA", sso: "SSO & Fédération",
    agents: "Agents IA & INH", workload: "Identité des charges de travail", eid: "eID européens",
    developers: "Expérience développeur", security: "Sécurité & Conformité",
    forDevs: "Pour les développeurs", forSec: "Pour la sécurité & les RSSI", forAi: "Pour les équipes IA & plateforme", forGov: "Secteur public & réglementé",
    about: "À propos", trust: "Confiance & sécurité", blog: "Blog",
  },
  cta: { book: "Demander une démo", docs: "Lire la documentation", explore: "Explorer la plateforme", learn: "En savoir plus", fine: "Sans carte bancaire. Auto-hébergeable. Conçu en Europe.", bandTitle: "Découvrez HelixIAM sur votre propre infrastructure.", bandSub: "Une démo de 30 minutes : realms, agents, identité des charges de travail et une migration en direct depuis Keycloak — adaptée à votre cas d'usage." },
  footer: { tag: "La plateforme d'identité européenne pour les humains, les agents IA et les charges de travail.", sovereign: "Souverain par conception", standards: "Standards ouverts", product: "Produit", solutions: "Solutions", developers: "Développeurs", company: "Entreprise", rights: "Un produit KubeDNA. Conçu en Europe.", privacy: "Confidentialité", terms: "Conditions", security: "Sécurité" },
  langLabel: "Langue",
  ui: {
    explore: "Explorer", view: "Voir", exploreMore: "Explorer davantage la plateforme",
    seeTheFit: "Voir l'adéquation", relevantCapabilities: "Capacités pertinentes",
    featureComplete: "Complet", everythingShipped: "Tout est livré et documenté.",
    comingSoon: "Bientôt disponible", whatNext: "Nos prochains articles",
    docsDeepest: "En attendant, la documentation est la source de vérité la plus complète.",
    backHome: "Retour à l'accueil", explorePlatform: "Explorer la plateforme", notFoundEyebrow: "404",
    legalEyebrow: "Mentions légales", legalUpdated: "Dernière mise à jour :",
    legalNote: "Ceci est un modèle destiné à être revu et complété par le conseil juridique de HelixIAM / KubeDNA avant publication. Les espaces réservés entre [crochets] doivent être remplacés par les informations de l'entité juridique exploitante.",
  },
  form: {
    name: "Nom complet", email: "E-mail professionnel", company: "Entreprise", role: "Votre rôle",
    roleSelect: "Sélectionner…", roleDev: "Développeur / Ingénieur", roleSec: "Sécurité / RSSI",
    roleAi: "IA / Plateforme", roleProduct: "Produit / Direction", rolePublic: "Secteur public", roleOther: "Autre",
    msgDemo: "Que souhaitez-vous voir ?", msgContact: "Comment pouvons-nous vous aider ?",
    phDemo: "ex. migration depuis Keycloak, identité des agents IA, DigiD…", phContact: "Parlez-nous un peu de votre cas d'usage.",
    consentPre: "J'accepte d'être contacté au sujet de HelixIAM et j'accepte la ", privacyPolicy: "politique de confidentialité", consentPost: ".",
    submitDemo: "Demander ma démo", submitContact: "Envoyer le message",
    fine: "Nous répondons sous un jour ouvré. Jamais de spam.",
    errName: "Veuillez saisir votre nom.", errEmail: "Veuillez saisir un e-mail professionnel valide.",
    errCompany: "Veuillez saisir votre entreprise.", errMessage: "Veuillez ajouter un court message.",
    errConsent: "Veuillez accepter la politique de confidentialité pour continuer.",
    successTitle: "Merci — vous êtes dans la file.",
    successPre: "Nous avons bien reçu votre demande et un membre de l'équipe vous recontactera sous un jour ouvré. En attendant, la ",
    documentation: "documentation", successPost: " est un excellent point de départ.",
  },
  home: {
    eyebrow: "L'identité pour les humains · agents IA · charges de travail",
    h1a: "L'identité, dans votre ", h1b: "ADN", h1c: ".",
    lead: "HelixIAM est la plateforme d'identité pour l'entreprise à l'ère des agents IA. Authentifiez, autorisez et gouvernez <strong>chaque identité — humaine et non humaine</strong> : vos collaborateurs, leurs agents IA et les charges de travail qui agissent en leur nom. SSO, MFA et fédération de classe Keycloak, identité des agents et des charges de travail conçue sur mesure, et souveraineté des données dans l'UE — depuis une seule plateforme.",
    trust: ["Standards ouverts — OIDC, SAML, FAPI, WebAuthn. Sans verrouillage.", "Souveraine dans l'UE & auto-hébergeable", "Conçue pour l'identité des agents IA & des charges de travail"],
    humanLabel: "Identité humaine", nhLabel: "Agents & charges de travail",
    logos: "Conçu pour les équipes qui sécurisent les logiciels modernes — des scale-ups au secteur public",
    logoSlots: ["Votre plateforme", "Votre banque", "Votre SaaS", "Votre agence", "Votre ministère"],
    strandsEyebrow: "Une trame, deux brins",
    strandsTitleA: "Chaque identité que vos systèmes touchent — ", strandsTitleB: "sur une seule plateforme",
    strandsLead: "La plupart des IAM ont été conçus pour les humains, les machines ayant été ajoutées après coup. HelixIAM traite l'identité humaine et non humaine comme les deux brins de la même hélice — émises, gouvernées et révoquées de la même manière.",
    strands: [
      { title: "Identité humaine", blurb: "Passkeys sans mot de passe, MFA adaptatif, SSO et fédération pour chaque personne — employés, clients et citoyens.", points: ["Passkeys & WebAuthn", "MFA adaptatif basé sur le risque", "OIDC · SAML · social · LDAP", "eID de l'UE prêts à l'emploi"] },
      { title: "Identité non humaine", blurb: "Identité de premier plan pour les agents IA et les charges de travail — jetons à portée limitée, délégation « au nom de » et fédération sans clé.", points: ["Identités d'agents IA", "Délégation RFC 8693 (act-as)", "Fédération d'identité des charges de travail", "Atténuée, avec coupe-circuit"] },
    ],
    whyEyebrow: "Pourquoi HelixIAM", whyTitle: "Quatre raisons de changer.",
    diff: [
      { title: "Conçu pour les agents IA & les charges de travail", blurb: "Pas ajouté après coup. HelixIAM traite les agents IA et les charges de travail comme des sujets de premier plan — avec la délégation, l'atténuation et la gouvernance que la plupart des IAM n'ont tout simplement pas." },
      { title: "Souverain & européen", blurb: "Votre realm, vos clés, votre continent. Auto-hébergeable, clés de signature par realm, résidence des données dans l'UE, et DigiD / eHerkenning / eIDAS intégrés — pas un plugin." },
      { title: "Les standards au cœur", blurb: "OAuth 2.1, OIDC, SAML 2.0, WebAuthn, FAPI, DPoP, RFC 8693 & RFC 8628. Protocoles ouverts, zéro verrouillage et un chemin de migration propre depuis Keycloak." },
      { title: "Un après-midi, pas un trimestre", blurb: "Une console d'administration soignée, des SDK, un provider Terraform et une configuration-as-code complète. Realms, clients et flux sont versionnés comme le reste de votre stack." },
    ],
    agentChip: "Nouveau — Identité non humaine",
    agentTitleA: "Donnez à vos ", agentTitleB: "agents IA", agentTitleC: " une véritable identité.",
    agentLead: "Les agents agissent au nom des utilisateurs et appellent des outils de manière autonome. HelixIAM attribue à chaque agent sa propre identité, émet des jetons <strong>« au nom de »</strong> (RFC 8693) qui portent l'utilisateur <em>et</em> l'agent, et vous permet d'atténuer la portée, d'exiger le consentement et d'activer un coupe-circuit — instantanément.",
    agentPoints: ["Registre & cycle de vie des agents", "Délégation à portée intersectée", "Fédération d'identité des charges de travail (sans clé)", "Authentification OAuth 2.1 prête pour MCP"],
    agentCta1: "Explorer l'identité des agents", agentCta2: "Identité des charges de travail",
    capEyebrow: "Toute la plateforme",
    capTitleA: "Tout ce dont un IAM moderne a besoin — ", capTitleB: "et la prochaine étape aussi",
    capLead: "Un ensemble de fonctionnalités complet, de classe Keycloak. Tout est livré. Tout est documenté.",
    easeEyebrow: "Simple, volontairement", easeTitle: "De zéro à une connexion sécurisée en un après-midi.",
    ease: [
      { t: "Lancez un realm", d: "Un conteneur ou un chart Helm. Importez votre realm Keycloak, ou partez de zéro — chaque paramètre est config-as-code." },
      { t: "Ajoutez votre application", d: "Enregistrez un client OIDC ou SAML dans la console, ou déclarez-le dans Terraform. Passkeys et MFA sont activés par défaut." },
      { t: "Déployez & gouvernez", d: "Branchez le SDK, passez en production et surveillez chaque humain, agent et charge de travail en un seul endroit audité et révocable." },
    ],
    codeComment: "// Sans mot de passe en trois lignes — le SDK gère PKCE, passkeys & refresh.",
    codeComment2: "// passkey / MFA / SSO — votre flux, vos règles",
    euEyebrow: "Souverain par conception",
    euTitleA: "Votre realm. Vos clés. ", euTitleB: "Votre continent.",
    euLead: "HelixIAM s'exécute là où vous êtes — votre cloud, votre datacenter, isolé du réseau si nécessaire. Les clés de signature par realm ne quittent jamais votre contrôle, et les eID européens sont de premier plan, pas un plugin.",
    euPoints: ["Résidence des données & auto-hébergement dans l'UE", "Clés KMS par realm + rotation", "DigiD · eHerkenning · eIDAS intégrés", "Outils de droits RGPD inclus"],
    euCta: "eID européens & souveraineté",
    stats: [
      { value: "3", label: "sujets d'identité", sub: "humains · agents · charges de travail" },
      { value: "9", label: "facteurs d'auth", sub: "des passkeys au push mobile" },
      { value: "100%", label: "standards ouverts", sub: "aucun verrouillage propriétaire" },
      { value: "UE", label: "souverain par conception", sub: "vos clés, votre realm" },
    ],
  },
};

const nl: typeof en = {
  tagline: "Identiteit, in je DNA.",
  meta: {
    home: "HelixIAM is het Europese identiteitsplatform voor de onderneming in het AI-agent-tijdperk — authenticeer, autoriseer en beheer mensen, AI-agents en workloads vanuit één platform. SSO, MFA en federatie van Keycloak-niveau, doelgerichte non-human en workload-identiteit, en EU-eID's. Een KubeDNA-product.",
  },
  nav: {
    product: "Product", solutions: "Oplossingen", why: "Waarom HelixIAM", docs: "Docs", company: "Bedrijf",
    contact: "Contact", demo: "Demo aanvragen",
    platform: "Platformoverzicht", auth: "Authenticatie & MFA", sso: "SSO & Federatie",
    agents: "AI-agents & NHI", workload: "Workload-identiteit", eid: "Europese eID's",
    developers: "Ontwikkelaarservaring", security: "Beveiliging & Compliance",
    forDevs: "Voor ontwikkelaars", forSec: "Voor security & CISO's", forAi: "Voor AI- & platformteams", forGov: "Overheid & gereguleerd",
    about: "Over ons", trust: "Vertrouwen & beveiliging", blog: "Blog",
  },
  cta: { book: "Demo aanvragen", docs: "Lees de documentatie", explore: "Ontdek het platform", learn: "Meer informatie", fine: "Geen creditcard. Zelf te hosten. Ontwikkeld in Europa.", bandTitle: "Zie HelixIAM op je eigen stack.", bandSub: "Een demo van 30 minuten: realms, agents, workload-identiteit en een live migratie van Keycloak — afgestemd op jouw use case." },
  footer: { tag: "De Europese identiteitslaag voor mensen, AI-agents en workloads.", sovereign: "Soeverein van opzet", standards: "Open standaarden", product: "Product", solutions: "Oplossingen", developers: "Ontwikkelaars", company: "Bedrijf", rights: "Een KubeDNA-product. Ontwikkeld in Europa.", privacy: "Privacy", terms: "Voorwaarden", security: "Beveiliging" },
  langLabel: "Taal",
  ui: {
    explore: "Ontdek", view: "Bekijk", exploreMore: "Ontdek meer van het platform",
    seeTheFit: "Bekijk de match", relevantCapabilities: "Relevante mogelijkheden",
    featureComplete: "Volledig", everythingShipped: "Alles geleverd en gedocumenteerd.",
    comingSoon: "Binnenkort beschikbaar", whatNext: "Wat we hierna schrijven",
    docsDeepest: "Ondertussen is de documentatie de meest volledige bron van waarheid.",
    backHome: "Terug naar home", explorePlatform: "Ontdek het platform", notFoundEyebrow: "404",
    legalEyebrow: "Juridisch", legalUpdated: "Laatst bijgewerkt:",
    legalNote: "Dit is een sjabloon dat vóór publicatie moet worden beoordeeld en aangevuld door de juridische afdeling van HelixIAM / KubeDNA. Plaatsaanduidingen tussen [haken] moeten worden vervangen door de gegevens van de exploiterende juridische entiteit.",
  },
  form: {
    name: "Volledige naam", email: "Zakelijk e-mailadres", company: "Bedrijf", role: "Je rol",
    roleSelect: "Selecteer…", roleDev: "Ontwikkelaar / Engineer", roleSec: "Security / CISO",
    roleAi: "AI / Platform", roleProduct: "Product / Management", rolePublic: "Overheid", roleOther: "Anders",
    msgDemo: "Wat wil je graag zien?", msgContact: "Hoe kunnen we je helpen?",
    phDemo: "bijv. migreren van Keycloak, AI-agent-identiteit, DigiD…", phContact: "Vertel ons kort over je use case.",
    consentPre: "Ik ga ermee akkoord om over HelixIAM te worden benaderd en accepteer het ", privacyPolicy: "privacybeleid", consentPost: ".",
    submitDemo: "Vraag mijn demo aan", submitContact: "Bericht versturen",
    fine: "We reageren binnen één werkdag. Nooit spam.",
    errName: "Vul je naam in.", errEmail: "Vul een geldig zakelijk e-mailadres in.",
    errCompany: "Vul je bedrijf in.", errMessage: "Voeg een kort bericht toe.",
    errConsent: "Accepteer het privacybeleid om door te gaan.",
    successTitle: "Bedankt — je staat in de wachtrij.",
    successPre: "We hebben je aanvraag ontvangen en iemand van het team neemt binnen één werkdag contact op. Ontdek ondertussen gerust de ",
    documentation: "documentatie", successPost: ".",
  },
  home: {
    eyebrow: "Identiteit voor mensen · AI-agents · workloads",
    h1a: "Identiteit, in je ", h1b: "DNA", h1c: ".",
    lead: "HelixIAM is het identiteitsplatform voor de onderneming in het AI-agent-tijdperk. Authenticeer, autoriseer en beheer <strong>elke identiteit — menselijk en niet-menselijk</strong>: uw mensen, hun AI-agents en de workloads die namens hen handelen. SSO, MFA en federatie van Keycloak-niveau, doelgerichte agent- en workload-identiteit, en EU-datasoevereiniteit — vanuit één platform.",
    trust: ["Open standaarden — OIDC, SAML, FAPI, WebAuthn. Geen lock-in.", "EU-soeverein & zelf te hosten", "Doelgericht voor AI-agent- & workload-identiteit"],
    humanLabel: "Menselijke identiteit", nhLabel: "Agents & workloads",
    logos: "Gebouwd voor teams die moderne software beveiligen — van scale-ups tot de overheid",
    logoSlots: ["Jouw platform", "Jouw bank", "Jouw SaaS", "Jouw organisatie", "Jouw ministerie"],
    strandsEyebrow: "Één laag, twee strengen",
    strandsTitleA: "Elke identiteit die je systemen raken — ", strandsTitleB: "op één platform",
    strandsLead: "De meeste IAM is gebouwd voor mensen, met machines er later aan vastgeplakt. HelixIAM behandelt menselijke en non-human identity als de twee strengen van dezelfde helix — op dezelfde manier uitgegeven, beheerd en ingetrokken.",
    strands: [
      { title: "Menselijke identiteit", blurb: "Wachtwoordloze passkeys, adaptieve MFA, SSO en federatie voor elke persoon — medewerkers, klanten en burgers.", points: ["Passkeys & WebAuthn", "Adaptieve, risicogebaseerde MFA", "OIDC · SAML · social · LDAP", "EU-eID's direct beschikbaar"] },
      { title: "Non-human identity", blurb: "Eersteklas identiteit voor AI-agents en workloads — tokens met beperkte scope, 'namens'-delegatie en sleutelloze federatie.", points: ["AI-agent-identiteiten", "RFC 8693-delegatie (act-as)", "Workload Identity Federation", "Beperkt, met kill-switch"] },
    ],
    whyEyebrow: "Waarom HelixIAM", whyTitle: "Vier redenen om over te stappen.",
    diff: [
      { title: "Gebouwd voor AI-agents & workloads", blurb: "Niet er later aan vastgeplakt. HelixIAM behandelt AI-agents en machine-workloads als eersteklas subjecten — met delegatie, beperking en governance die de meeste IAM's simpelweg niet hebben." },
      { title: "Soeverein & Europees", blurb: "Jouw realm, jouw sleutels, jouw continent. Zelf te hosten, ondertekeningssleutels per realm, EU-dataresidentie, en DigiD / eHerkenning / eIDAS ingebouwd — geen plugin." },
      { title: "Standaarden tot in de kern", blurb: "OAuth 2.1, OIDC, SAML 2.0, WebAuthn, FAPI, DPoP, RFC 8693 & RFC 8628. Open protocollen, geen lock-in, en een schoon migratiepad weg van Keycloak." },
      { title: "Een middag, geen kwartaal", blurb: "Een verzorgde adminconsole, SDK's, een Terraform-provider en volledige config-as-code. Realms, clients en flows worden geversioneerd net als de rest van je stack." },
    ],
    agentChip: "Nieuw — Non-Human Identity",
    agentTitleA: "Geef je ", agentTitleB: "AI-agents", agentTitleC: " een echte identiteit.",
    agentLead: "Agents handelen namens gebruikers en roepen zelfstandig tools aan. HelixIAM geeft elke agent een eigen identiteit, geeft <strong>'namens'</strong>-tokens uit (RFC 8693) die de gebruiker <em>én</em> de agent dragen, en laat je de scope beperken, toestemming eisen en direct een kill-switch omzetten.",
    agentPoints: ["Agent-register & levenscyclus", "Delegatie met doorsneden scope", "Workload Identity Federation (sleutelloos)", "MCP-klare OAuth 2.1-auth"],
    agentCta1: "Ontdek agent-identiteit", agentCta2: "Workload-identiteit",
    capEyebrow: "Het hele platform",
    capTitleA: "Alles wat een modern IAM nodig heeft — ", capTitleB: "en het volgende ook",
    capLead: "Een complete featureset van Keycloak-niveau. Allemaal geleverd. Allemaal gedocumenteerd.",
    easeEyebrow: "Bewust eenvoudig", easeTitle: "Van nul naar veilige login in een middag.",
    ease: [
      { t: "Start een realm", d: "Eén container of een Helm-chart. Importeer je Keycloak-realm, of begin opnieuw — elke instelling is config-as-code." },
      { t: "Voeg je app toe", d: "Registreer een OIDC- of SAML-client in de console, of declareer die in Terraform. Passkeys en MFA staan standaard aan." },
      { t: "Lanceer & beheer", d: "Koppel de SDK, ga live en beheer elke mens, agent en workload op één geaudite, intrekbare plek." },
    ],
    codeComment: "// Wachtwoordloos in drie regels — de SDK regelt PKCE, passkeys & refresh.",
    codeComment2: "// passkey / MFA / SSO — jouw flow, jouw regels",
    euEyebrow: "Soeverein van opzet",
    euTitleA: "Jouw realm. Jouw sleutels. ", euTitleB: "Jouw continent.",
    euLead: "HelixIAM draait waar jij draait — je eigen cloud, je datacenter, air-gapped indien nodig. Ondertekeningssleutels per realm verlaten nooit je beheer, en Europa's eID's zijn eersteklas, geen plugin.",
    euPoints: ["EU-dataresidentie & zelf hosten", "KMS-sleutels per realm + rotatie", "DigiD · eHerkenning · eIDAS ingebouwd", "AVG-rechtentooling inbegrepen"],
    euCta: "Europese eID's & soevereiniteit",
    stats: [
      { value: "3", label: "identiteitssubjecten", sub: "mensen · agents · workloads" },
      { value: "9", label: "auth-factoren", sub: "van passkeys tot device push" },
      { value: "100%", label: "open standaarden", sub: "geen propriëtaire lock-in" },
      { value: "EU", label: "soeverein van opzet", sub: "jouw sleutels, jouw realm" },
    ],
  },
};

export const STR = { en, fr, nl } as const;
export type { Dict };
