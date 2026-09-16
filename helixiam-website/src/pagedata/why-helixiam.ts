import type { Locale } from "../i18n";

export interface DiffCard {
  icon: string;
  title: string;
  blurb: string;
  href: string;
}

export interface CmpRow {
  f: string;
  h: boolean | string;
  k: boolean | string;
}

export interface WhyStr {
  metaTitle: string;
  metaDesc: string;
  eyebrow: string;
  title: string;
  lead: string;
  diffs: DiffCard[];
  cmpEyebrow: string;
  cmpTitle: string;
  cmpLead: string;
  colCapability: string;
  colTypical: string;
  partialLabel: string;
  naLabel: string;
  rows: CmpRow[];
  cmpNote: string;
  ctaTitle: string;
  ctaSub: string;
}

export const whyHelixiam: Record<Locale, WhyStr> = {
  en: {
    metaTitle: "Why HelixIAM",
    metaDesc:
      "Why teams choose HelixIAM over Keycloak and legacy IAM: first-class AI-agent and workload identity, European sovereignty, and a clean migration path.",
    eyebrow: "Why HelixIAM",
    title: 'Keycloak-class today. <span class="grad-text">Ready for tomorrow.</span>',
    lead: "HelixIAM gives you everything Keycloak does — then adds the things modern software actually needs: identity for AI agents and workloads, European eIDs, and provable sovereignty. With an importer that migrates you in.",
    diffs: [
      {
        icon: "agent",
        title: "Built for AI agents & workloads",
        blurb:
          "Not bolted on. HelixIAM treats AI agents and machine workloads as first-class subjects — with delegation, attenuation, and governance most IAMs simply don't have.",
        href: "/product/ai-agents/",
      },
      {
        icon: "eu",
        title: "Sovereign & European",
        blurb:
          "Your realm, your keys, your continent. Self-hostable, per-realm signing keys, EU data residency, and DigiD / eHerkenning / eIDAS built in — not a plugin.",
        href: "/product/european-eid/",
      },
      {
        icon: "protocol",
        title: "Standards to the core",
        blurb:
          "OAuth 2.1, OIDC, SAML 2.0, WebAuthn, FAPI, DPoP, RFC 8693 & RFC 8628. Open protocols, zero lock-in, and a clean migration path off Keycloak.",
        href: "/product/security/",
      },
      {
        icon: "dev",
        title: "An afternoon, not a quarter",
        blurb:
          "A polished admin console, SDKs, a Terraform provider, and full config-as-code. Realms, clients, and flows are versioned like the rest of your stack.",
        href: "/product/developers/",
      },
    ],
    cmpEyebrow: "Head to head",
    cmpTitle: "HelixIAM vs. Keycloak & legacy IAM.",
    cmpLead:
      "The open-standards foundation you expect — plus the capabilities most IAMs are only starting to think about.",
    colCapability: "Capability",
    colTypical: "Typical / Keycloak",
    partialLabel: "partial",
    naLabel: "n/a",
    rows: [
      { f: "OIDC / OAuth 2.1 provider", h: true, k: true },
      { f: "SAML 2.0 IdP & SP", h: true, k: true },
      { f: "Passkeys, OTP, device push, adaptive MFA", h: true, k: "partial" },
      { f: "AI-agent identity (registry + lifecycle)", h: true, k: false },
      { f: "On-behalf-of delegation (RFC 8693)", h: true, k: false },
      { f: "Workload Identity Federation (keyless)", h: true, k: "partial" },
      { f: "DigiD · eHerkenning · eIDAS built in", h: true, k: false },
      { f: "FAPI · DPoP · mTLS-bound tokens", h: true, k: "partial" },
      { f: "Config-as-code + Terraform provider", h: true, k: "partial" },
      { f: "Keycloak importer (migrate in)", h: true, k: "n/a" },
      { f: "European, sovereign, self-hostable", h: true, k: true },
    ],
    cmpNote:
      'Comparison reflects HelixIAM\'s shipped capabilities. "Partial" indicates add-ons, plugins, or extra engineering typically required elsewhere.',
    ctaTitle: "Migrate in a weekend, not a quarter.",
    ctaSub:
      "Import your Keycloak realms, clients, and users — then turn on the things you couldn't before. Let's map your migration on a call.",
  },
  fr: {
    metaTitle: "Pourquoi HelixIAM",
    metaDesc:
      "Pourquoi les équipes choisissent HelixIAM plutôt que Keycloak et les IAM historiques : identité de premier plan pour les agents IA et les charges de travail, souveraineté européenne et un chemin de migration propre.",
    eyebrow: "Pourquoi HelixIAM",
    title: 'De classe Keycloak aujourd\'hui. <span class="grad-text">Prêt pour demain.</span>',
    lead: "HelixIAM vous offre tout ce que fait Keycloak — puis ajoute ce dont les logiciels modernes ont réellement besoin : l'identité des agents IA et des charges de travail, les eID européens et une souveraineté démontrable. Avec un importateur qui assure votre migration.",
    diffs: [
      {
        icon: "agent",
        title: "Conçu pour les agents IA & les charges de travail",
        blurb:
          "Pas ajouté après coup. HelixIAM traite les agents IA et les charges de travail comme des sujets de premier plan — avec la délégation, l'atténuation et la gouvernance que la plupart des IAM n'ont tout simplement pas.",
        href: "/product/ai-agents/",
      },
      {
        icon: "eu",
        title: "Souverain & européen",
        blurb:
          "Votre realm, vos clés, votre continent. Auto-hébergeable, clés de signature par realm, résidence des données dans l'UE, et DigiD / eHerkenning / eIDAS intégrés — pas un plugin.",
        href: "/product/european-eid/",
      },
      {
        icon: "protocol",
        title: "Les standards au cœur",
        blurb:
          "OAuth 2.1, OIDC, SAML 2.0, WebAuthn, FAPI, DPoP, RFC 8693 & RFC 8628. Protocoles ouverts, zéro verrouillage et un chemin de migration propre depuis Keycloak.",
        href: "/product/security/",
      },
      {
        icon: "dev",
        title: "Un après-midi, pas un trimestre",
        blurb:
          "Une console d'administration soignée, des SDK, un provider Terraform et une configuration-as-code complète. Realms, clients et flux sont versionnés comme le reste de votre stack.",
        href: "/product/developers/",
      },
    ],
    cmpEyebrow: "Face à face",
    cmpTitle: "HelixIAM vs. Keycloak & les IAM historiques.",
    cmpLead:
      "La base de standards ouverts que vous attendez — plus les capacités auxquelles la plupart des IAM commencent tout juste à penser.",
    colCapability: "Capacité",
    colTypical: "Typique / Keycloak",
    partialLabel: "Partiel",
    naLabel: "s/o",
    rows: [
      { f: "OIDC / OAuth 2.1 provider", h: true, k: true },
      { f: "SAML 2.0 IdP & SP", h: true, k: true },
      { f: "Passkeys, OTP, device push, MFA adaptatif", h: true, k: "partial" },
      { f: "Identité des agents IA (registre + cycle de vie)", h: true, k: false },
      { f: "Délégation « au nom de » (RFC 8693)", h: true, k: false },
      { f: "Workload Identity Federation (sans clé)", h: true, k: "partial" },
      { f: "DigiD · eHerkenning · eIDAS intégrés", h: true, k: false },
      { f: "Jetons liés FAPI · DPoP · mTLS", h: true, k: "partial" },
      { f: "Config-as-code + provider Terraform", h: true, k: "partial" },
      { f: "Importateur Keycloak (migration entrante)", h: true, k: "n/a" },
      { f: "Européen, souverain, auto-hébergeable", h: true, k: true },
    ],
    cmpNote:
      'La comparaison reflète les capacités livrées de HelixIAM. « Partiel » indique des add-ons, des plugins ou des développements supplémentaires généralement requis ailleurs.',
    ctaTitle: "Migrez en un week-end, pas en un trimestre.",
    ctaSub:
      "Importez vos realms, clients et utilisateurs Keycloak — puis activez ce que vous ne pouviez pas avant. Planifions votre migration lors d'un appel.",
  },
  nl: {
    metaTitle: "Waarom HelixIAM",
    metaDesc:
      "Waarom teams voor HelixIAM kiezen in plaats van Keycloak en legacy-IAM: eersteklas AI-agent- en workload-identiteit, Europese soevereiniteit en een schoon migratiepad.",
    eyebrow: "Waarom HelixIAM",
    title: 'Vandaag van Keycloak-niveau. <span class="grad-text">Klaar voor morgen.</span>',
    lead: "HelixIAM geeft je alles wat Keycloak doet — en voegt er vervolgens toe wat moderne software echt nodig heeft: identiteit voor AI-agents en workloads, Europese eID's en aantoonbare soevereiniteit. Met een importer die je binnenhaalt.",
    diffs: [
      {
        icon: "agent",
        title: "Gebouwd voor AI-agents & workloads",
        blurb:
          "Niet er later aan vastgeplakt. HelixIAM behandelt AI-agents en machine-workloads als eersteklas subjecten — met delegatie, beperking en governance die de meeste IAM's simpelweg niet hebben.",
        href: "/product/ai-agents/",
      },
      {
        icon: "eu",
        title: "Soeverein & Europees",
        blurb:
          "Jouw realm, jouw sleutels, jouw continent. Zelf te hosten, ondertekeningssleutels per realm, EU-dataresidentie, en DigiD / eHerkenning / eIDAS ingebouwd — geen plugin.",
        href: "/product/european-eid/",
      },
      {
        icon: "protocol",
        title: "Standaarden tot in de kern",
        blurb:
          "OAuth 2.1, OIDC, SAML 2.0, WebAuthn, FAPI, DPoP, RFC 8693 & RFC 8628. Open protocollen, geen lock-in, en een schoon migratiepad weg van Keycloak.",
        href: "/product/security/",
      },
      {
        icon: "dev",
        title: "Een middag, geen kwartaal",
        blurb:
          "Een verzorgde adminconsole, SDK's, een Terraform-provider en volledige config-as-code. Realms, clients en flows worden geversioneerd net als de rest van je stack.",
        href: "/product/developers/",
      },
    ],
    cmpEyebrow: "Kop aan kop",
    cmpTitle: "HelixIAM vs. Keycloak & legacy-IAM.",
    cmpLead:
      "Het fundament van open standaarden dat je verwacht — plus de mogelijkheden waar de meeste IAM's pas net over beginnen na te denken.",
    colCapability: "Mogelijkheid",
    colTypical: "Typisch / Keycloak",
    partialLabel: "gedeeltelijk",
    naLabel: "n.v.t.",
    rows: [
      { f: "OIDC / OAuth 2.1 provider", h: true, k: true },
      { f: "SAML 2.0 IdP & SP", h: true, k: true },
      { f: "Passkeys, OTP, device push, adaptieve MFA", h: true, k: "partial" },
      { f: "AI-agent-identiteit (register + levenscyclus)", h: true, k: false },
      { f: "'Namens'-delegatie (RFC 8693)", h: true, k: false },
      { f: "Workload Identity Federation (sleutelloos)", h: true, k: "partial" },
      { f: "DigiD · eHerkenning · eIDAS ingebouwd", h: true, k: false },
      { f: "FAPI · DPoP · mTLS-gebonden tokens", h: true, k: "partial" },
      { f: "Config-as-code + Terraform-provider", h: true, k: "partial" },
      { f: "Keycloak-importer (naar binnen migreren)", h: true, k: "n/a" },
      { f: "Europees, soeverein, zelf te hosten", h: true, k: true },
    ],
    cmpNote:
      'De vergelijking weerspiegelt de geleverde mogelijkheden van HelixIAM. "Gedeeltelijk" duidt op add-ons, plugins of extra engineering die elders doorgaans nodig zijn.',
    ctaTitle: "Migreer in een weekend, geen kwartaal.",
    ctaSub:
      "Importeer je Keycloak-realms, -clients en -gebruikers — zet daarna aan wat eerder niet kon. Laten we je migratie in een gesprek uitstippelen.",
  },
};
