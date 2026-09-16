import type { Locale } from "../i18n";

export interface Solution {
  slug: string;
  navLabel: string;
  icon: string;
  eyebrow: string;
  title: string;
  lead: string;
  metaDesc: string;
  rows: { heading: string; body: string; bullets: string[]; icon?: string }[];
  productLinks: { label: string; href: string }[];
}

export const SOLUTIONS: Solution[] = [
  {
    slug: "developers",
    navLabel: "For developers",
    icon: "code",
    eyebrow: "For developers",
    title: 'Ship login <span class="grad-text">this afternoon</span>.',
    lead: "Stop hand-rolling auth. HelixIAM gives you standards-based login, an SDK, and identity-as-code so you can wire secure sign-in and get back to your product.",
    metaDesc: "HelixIAM for developers: TypeScript SDK, OIDC/SAML, Terraform provider, config-as-code and a 5-minute quickstart.",
    rows: [
      { heading: "Minutes to first login", icon: "bolt", body: "Install the SDK, point it at your realm, call login(). Passkeys, MFA, refresh, and PKCE are handled for you — across any framework.", bullets: ["Official TypeScript SDK + adapters", "5-minute quickstart", "OIDC & SAML out of the box", "OpenAPI + Swagger UI"] },
      { heading: "Identity as code", icon: "layers", body: "Realms, clients, scopes, and flows are declarable. Review them in a PR, apply them in CI, and keep dev/staging/prod identical.", bullets: ["Terraform provider", "Config-as-code import/export", "Env-var secret substitution", "Keycloak importer to migrate in"] },
      { heading: "Auth for your agents too", icon: "agent", body: "Building with LLMs? Give each agent an identity and mint on-behalf-of tokens so autonomous calls are traceable and revocable.", bullets: ["AI-agent identities", "RFC 8693 delegation", "Workload identity federation", "MCP-ready OAuth 2.1"] },
    ],
    productLinks: [{ label: "Developer experience", href: "/product/developers/" }, { label: "AI agents & NHI", href: "/product/ai-agents/" }, { label: "Authentication & MFA", href: "/product/authentication/" }],
  },
  {
    slug: "security-teams",
    navLabel: "For security & CISOs",
    icon: "shield",
    eyebrow: "For security & CISOs",
    title: 'Provable control, <span class="grad-text">European sovereignty</span>.',
    lead: "Phishing-resistant auth, sender-constrained tokens, keys you hold, and an audit trail that streams to your SIEM — running in your own environment, not someone else's cloud.",
    metaDesc: "HelixIAM for security teams and CISOs: FAPI/DPoP, per-realm keys, searchable audit, SIEM streaming, EU sovereignty.",
    rows: [
      { heading: "Kill phishing & replay", icon: "finger", body: "Passkeys make credential phishing pointless; DPoP and mTLS binding make stolen tokens useless. Adaptive risk catches the rest.", bullets: ["WebAuthn passkeys", "DPoP + mTLS-bound tokens", "FAPI client policies", "Risk-based adaptive MFA"] },
      { heading: "Own your keys & data", icon: "key", body: "Self-host in the EU with per-realm signing keys and zero-downtime rotation. No foreign control plane, no vendor holding your secrets.", bullets: ["Self-hostable, EU residency", "Per-realm KMS/HSM keys", "Zero-downtime rotation", "HA topology + benchmarks"] },
      { heading: "Prove it to auditors", icon: "eye", body: "Every login and admin action is persisted and searchable, streams to your SIEM, and impersonation is fully traced. GDPR rights are one click.", bullets: ["Searchable audit log", "SIEM streaming + signed webhooks", "Fine-grained admin RBAC", "GDPR rights tooling"] },
    ],
    productLinks: [{ label: "Security & compliance", href: "/product/security/" }, { label: "European eIDs", href: "/product/european-eid/" }, { label: "Trust center", href: "/trust/" }],
  },
  {
    slug: "ai-teams",
    navLabel: "For AI & platform teams",
    icon: "agent",
    eyebrow: "For AI & platform teams",
    title: 'Govern every <span class="grad-text">agent and workload</span>.',
    lead: "Agentic systems multiply non-human identities fast. HelixIAM gives each one a real identity, least-privilege delegation, and a kill-switch — so autonomy never means loss of control.",
    metaDesc: "HelixIAM for AI and platform teams: agent identity, RFC 8693 delegation, workload identity federation, kill-switch governance.",
    rows: [
      { heading: "Every agent, accountable", icon: "agent", body: "Register agents as owned, named identities. Their tokens are scoped, short-lived, and traceable to the human they act for.", bullets: ["Agent registry & lifecycle", "On-behalf-of tokens (sub + act)", "Scope intersection & attenuation", "Consent capture"] },
      { heading: "Keyless workloads", icon: "cloud", body: "Kubernetes and CI already have signed identities. Exchange them for HelixIAM tokens — no long-lived secrets to leak or rotate.", bullets: ["K8s / CI JWT exchange", "Bound to service-account roles", "Short-lived, audience-bound", "Instant revocation"] },
      { heading: "Contain the blast radius", icon: "shield", body: "Delegated authority can only narrow. Cap scope and lifetime, and pull a realm-wide kill-switch the moment an agent misbehaves.", bullets: ["Monotonic scope narrowing", "Realm-wide kill-switch", "NHI inventory & ownership", "MCP-ready auth"] },
    ],
    productLinks: [{ label: "AI agents & NHI", href: "/product/ai-agents/" }, { label: "Workload identity", href: "/product/workload-identity/" }, { label: "Security & compliance", href: "/product/security/" }],
  },
  {
    slug: "public-sector",
    navLabel: "Public sector & regulated",
    icon: "eu",
    eyebrow: "Public sector & regulated",
    title: 'European eIDs, <span class="grad-text">without the integration project</span>.',
    lead: "DigiD, eHerkenning, and eIDAS are first-class brokers with the right assurance levels. Deploy sovereign, brand each realm, and meet GDPR and FAPI where it matters.",
    metaDesc: "HelixIAM for public sector and regulated industries: DigiD, eHerkenning, eIDAS, assurance levels, sovereignty and GDPR.",
    rows: [
      { heading: "The eIDs, built in", icon: "eu", body: "Citizens and businesses sign in with credentials they already trust — brokered with correct assurance levels, not a bespoke integration.", bullets: ["DigiD (NL citizen)", "eHerkenning (NL business)", "eIDAS (EU cross-border)", "Assurance-level enforcement"] },
      { heading: "Sovereign & branded", icon: "cloud", body: "Run in your own or a national cloud, air-gap if needed, and theme each realm — with Dutch localization out of the box.", bullets: ["Self-hostable, EU residency", "Per-realm login theming", "nl-NL localization", "Per-realm signing keys"] },
      { heading: "Compliance you can show", icon: "shield", body: "FAPI-grade token security, a searchable audit trail, and GDPR rights tooling give you the evidence regulators ask for.", bullets: ["FAPI + DPoP + mTLS", "Searchable audit + SIEM", "GDPR rights tooling", "Fine-grained admin RBAC"] },
    ],
    productLinks: [{ label: "European eIDs", href: "/product/european-eid/" }, { label: "Security & compliance", href: "/product/security/" }, { label: "SSO & federation", href: "/product/sso-federation/" }],
  },
];

export const solutionBySlug = (s: string) => SOLUTIONS.find((x) => x.slug === s);

export const SOLUTIONS_FR: Solution[] = [
  {
    slug: "developers",
    navLabel: "Pour les développeurs",
    icon: "code",
    eyebrow: "Pour les développeurs",
    title: 'Déployez le login <span class="grad-text">cet après-midi</span>.',
    lead: "Arrêtez de coder l'authentification à la main. HelixIAM vous offre un login basé sur les standards, un SDK et l'identity-as-code : câblez une connexion sécurisée et revenez à votre produit.",
    metaDesc: "HelixIAM pour les développeurs : SDK TypeScript, OIDC/SAML, provider Terraform, config-as-code et un démarrage rapide en 5 minutes.",
    rows: [
      { heading: "Le premier login en quelques minutes", icon: "bolt", body: "Installez le SDK, pointez-le vers votre realm, appelez login(). Passkeys, MFA, refresh et PKCE sont pris en charge pour vous — sur n'importe quel framework.", bullets: ["SDK TypeScript officiel + adaptateurs", "Démarrage rapide en 5 minutes", "OIDC & SAML prêts à l'emploi", "OpenAPI + Swagger UI"] },
      { heading: "L'identité comme du code", icon: "layers", body: "Realms, clients, scopes et flows sont déclaratifs. Revoyez-les dans une PR, appliquez-les en CI et gardez dev/staging/prod identiques.", bullets: ["Provider Terraform", "Import/export config-as-code", "Substitution de secrets par variable d'environnement", "Importeur Keycloak pour migrer"] },
      { heading: "L'authentification pour vos agents aussi", icon: "agent", body: "Vous développez avec des LLM ? Donnez une identité à chaque agent et émettez des tokens on-behalf-of pour que les appels autonomes soient traçables et révocables.", bullets: ["Identités d'agents IA", "Délégation RFC 8693", "Workload identity federation", "OAuth 2.1 prêt pour MCP"] },
    ],
    productLinks: [{ label: "Expérience développeur", href: "/product/developers/" }, { label: "Agents IA & NHI", href: "/product/ai-agents/" }, { label: "Authentification & MFA", href: "/product/authentication/" }],
  },
  {
    slug: "security-teams",
    navLabel: "Pour la sécurité & les RSSI",
    icon: "shield",
    eyebrow: "Pour la sécurité & les RSSI",
    title: 'Un contrôle prouvable, <span class="grad-text">une souveraineté européenne</span>.',
    lead: "Une authentification résistante au phishing, des tokens liés à leur émetteur, des clés que vous détenez et une piste d'audit qui alimente votre SIEM — le tout dans votre propre environnement, pas dans le cloud de quelqu'un d'autre.",
    metaDesc: "HelixIAM pour les équipes de sécurité et les RSSI : FAPI/DPoP, clés par realm, audit interrogeable, streaming SIEM, souveraineté européenne.",
    rows: [
      { heading: "Éliminez phishing & rejeu", icon: "finger", body: "Les passkeys rendent le phishing d'identifiants inutile ; le binding DPoP et mTLS rend les tokens volés inexploitables. Le risque adaptatif couvre le reste.", bullets: ["Passkeys WebAuthn", "Tokens liés à DPoP + mTLS", "Politiques client FAPI", "MFA adaptatif basé sur le risque"] },
      { heading: "Maîtrisez vos clés & vos données", icon: "key", body: "Auto-hébergez dans l'UE avec des clés de signature par realm et une rotation sans interruption. Aucun plan de contrôle étranger, aucun fournisseur qui détient vos secrets.", bullets: ["Auto-hébergeable, résidence UE", "Clés KMS/HSM par realm", "Rotation sans interruption", "Topologie HA + benchmarks"] },
      { heading: "Prouvez-le aux auditeurs", icon: "eye", body: "Chaque connexion et chaque action d'administration est persistée et interrogeable, alimente votre SIEM, et l'impersonation est entièrement tracée. Les droits RGPD tiennent en un clic.", bullets: ["Journal d'audit interrogeable", "Streaming SIEM + webhooks signés", "RBAC d'administration fine", "Outillage des droits RGPD"] },
    ],
    productLinks: [{ label: "Sécurité & conformité", href: "/product/security/" }, { label: "eIDs européennes", href: "/product/european-eid/" }, { label: "Centre de confiance", href: "/trust/" }],
  },
  {
    slug: "ai-teams",
    navLabel: "Pour les équipes IA & plateforme",
    icon: "agent",
    eyebrow: "Pour les équipes IA & plateforme",
    title: 'Gouvernez chaque <span class="grad-text">agent et charge de travail</span>.',
    lead: "Les systèmes agentiques multiplient vite les identités non humaines. HelixIAM donne à chacune une vraie identité, une délégation au moindre privilège et un kill-switch — pour que l'autonomie ne signifie jamais la perte de contrôle.",
    metaDesc: "HelixIAM pour les équipes IA et plateforme : identité d'agent, délégation RFC 8693, workload identity federation, gouvernance par kill-switch.",
    rows: [
      { heading: "Chaque agent, responsable", icon: "agent", body: "Enregistrez les agents comme des identités nommées et rattachées à un propriétaire. Leurs tokens sont limités en scope, à courte durée de vie et traçables jusqu'à l'humain pour lequel ils agissent.", bullets: ["Registre & cycle de vie des agents", "Tokens on-behalf-of (sub + act)", "Intersection de scope & atténuation", "Capture du consentement"] },
      { heading: "Charges de travail sans clé", icon: "cloud", body: "Kubernetes et la CI ont déjà des identités signées. Échangez-les contre des tokens HelixIAM — aucun secret à longue durée de vie à fuiter ou à faire tourner.", bullets: ["Échange de JWT K8s / CI", "Lié aux rôles de service-account", "Courte durée de vie, lié à une audience", "Révocation instantanée"] },
      { heading: "Contenez le rayon d'impact", icon: "shield", body: "L'autorité déléguée ne peut que se restreindre. Plafonnez scope et durée de vie, et actionnez un kill-switch à l'échelle du realm dès qu'un agent dérape.", bullets: ["Réduction monotone du scope", "Kill-switch à l'échelle du realm", "Inventaire & propriété des NHI", "Auth prête pour MCP"] },
    ],
    productLinks: [{ label: "Agents IA & NHI", href: "/product/ai-agents/" }, { label: "Workload identity", href: "/product/workload-identity/" }, { label: "Sécurité & conformité", href: "/product/security/" }],
  },
  {
    slug: "public-sector",
    navLabel: "Secteur public & régulé",
    icon: "eu",
    eyebrow: "Secteur public & régulé",
    title: 'Les eIDs européennes, <span class="grad-text">sans le projet d\'intégration</span>.',
    lead: "DigiD, eHerkenning et eIDAS sont des brokers de premier plan avec les bons niveaux de garantie. Déployez souverainement, personnalisez chaque realm et respectez RGPD et FAPI là où ça compte.",
    metaDesc: "HelixIAM pour le secteur public et les secteurs régulés : DigiD, eHerkenning, eIDAS, niveaux de garantie, souveraineté et RGPD.",
    rows: [
      { heading: "Les eIDs, intégrées", icon: "eu", body: "Citoyens et entreprises se connectent avec des identifiants auxquels ils font déjà confiance — brokés avec les bons niveaux de garantie, pas via une intégration sur mesure.", bullets: ["DigiD (citoyen NL)", "eHerkenning (entreprise NL)", "eIDAS (transfrontalier UE)", "Application du niveau de garantie"] },
      { heading: "Souverain & personnalisé", icon: "cloud", body: "Fonctionnez dans votre propre cloud ou un cloud national, isolez-le si nécessaire, et thématisez chaque realm — avec une localisation néerlandaise prête à l'emploi.", bullets: ["Auto-hébergeable, résidence UE", "Thématisation du login par realm", "Localisation nl-NL", "Clés de signature par realm"] },
      { heading: "Une conformité démontrable", icon: "shield", body: "Une sécurité des tokens de niveau FAPI, une piste d'audit interrogeable et l'outillage des droits RGPD vous donnent les preuves que les régulateurs demandent.", bullets: ["FAPI + DPoP + mTLS", "Audit interrogeable + SIEM", "Outillage des droits RGPD", "RBAC d'administration fine"] },
    ],
    productLinks: [{ label: "eIDs européennes", href: "/product/european-eid/" }, { label: "Sécurité & conformité", href: "/product/security/" }, { label: "SSO & fédération", href: "/product/sso-federation/" }],
  },
];

export const SOLUTIONS_NL: Solution[] = [
  {
    slug: "developers",
    navLabel: "Voor ontwikkelaars",
    icon: "code",
    eyebrow: "Voor ontwikkelaars",
    title: 'Zet login live <span class="grad-text">vanmiddag nog</span>.',
    lead: "Stop met het zelf bouwen van authenticatie. HelixIAM geeft je login op basis van standaarden, een SDK en identity-as-code, zodat je veilige aanmelding koppelt en weer verder kunt met je product.",
    metaDesc: "HelixIAM voor ontwikkelaars: TypeScript SDK, OIDC/SAML, Terraform-provider, config-as-code en een quickstart van 5 minuten.",
    rows: [
      { heading: "Binnen minuten je eerste login", icon: "bolt", body: "Installeer de SDK, wijs hem naar je realm, roep login() aan. Passkeys, MFA, refresh en PKCE worden voor je afgehandeld — in elk framework.", bullets: ["Officiële TypeScript SDK + adapters", "Quickstart van 5 minuten", "OIDC & SAML direct beschikbaar", "OpenAPI + Swagger UI"] },
      { heading: "Identiteit als code", icon: "layers", body: "Realms, clients, scopes en flows zijn declareerbaar. Beoordeel ze in een PR, pas ze toe in CI en houd dev/staging/prod identiek.", bullets: ["Terraform-provider", "Config-as-code import/export", "Vervanging van secrets via omgevingsvariabelen", "Keycloak-importer om te migreren"] },
      { heading: "Authenticatie ook voor je agents", icon: "agent", body: "Bouw je met LLM's? Geef elke agent een identiteit en genereer on-behalf-of tokens, zodat autonome aanroepen traceerbaar en intrekbaar zijn.", bullets: ["AI-agent-identiteiten", "RFC 8693-delegatie", "Workload identity federation", "OAuth 2.1 klaar voor MCP"] },
    ],
    productLinks: [{ label: "Ontwikkelaarservaring", href: "/product/developers/" }, { label: "AI-agents & NHI", href: "/product/ai-agents/" }, { label: "Authenticatie & MFA", href: "/product/authentication/" }],
  },
  {
    slug: "security-teams",
    navLabel: "Voor security & CISO's",
    icon: "shield",
    eyebrow: "Voor security & CISO's",
    title: 'Aantoonbare controle, <span class="grad-text">Europese soevereiniteit</span>.',
    lead: "Phishingbestendige authenticatie, tokens gebonden aan hun afzender, sleutels die je zelf beheert en een auditlog die naar je SIEM streamt — draaiend in je eigen omgeving, niet in andermans cloud.",
    metaDesc: "HelixIAM voor securityteams en CISO's: FAPI/DPoP, sleutels per realm, doorzoekbare audit, SIEM-streaming, EU-soevereiniteit.",
    rows: [
      { heading: "Elimineer phishing & replay", icon: "finger", body: "Passkeys maken het phishen van credentials zinloos; DPoP- en mTLS-binding maken gestolen tokens waardeloos. Adaptief risico vangt de rest af.", bullets: ["WebAuthn-passkeys", "Tokens gebonden aan DPoP + mTLS", "FAPI-clientbeleid", "Risicogebaseerde adaptieve MFA"] },
      { heading: "Beheer je eigen sleutels & data", icon: "key", body: "Host zelf in de EU met signeersleutels per realm en rotatie zonder downtime. Geen buitenlands control plane, geen leverancier die je secrets vasthoudt.", bullets: ["Zelf te hosten, EU-dataresidentie", "KMS/HSM-sleutels per realm", "Rotatie zonder downtime", "HA-topologie + benchmarks"] },
      { heading: "Toon het aan auditors", icon: "eye", body: "Elke login en beheeractie wordt bewaard en is doorzoekbaar, streamt naar je SIEM, en impersonatie wordt volledig getraceerd. AVG-rechten regel je met één klik.", bullets: ["Doorzoekbare auditlog", "SIEM-streaming + ondertekende webhooks", "Fijnmazige admin-RBAC", "AVG-rechtentooling"] },
    ],
    productLinks: [{ label: "Beveiliging & compliance", href: "/product/security/" }, { label: "Europese eID's", href: "/product/european-eid/" }, { label: "Trust center", href: "/trust/" }],
  },
  {
    slug: "ai-teams",
    navLabel: "Voor AI- & platformteams",
    icon: "agent",
    eyebrow: "Voor AI- & platformteams",
    title: 'Beheer elke <span class="grad-text">agent en workload</span>.',
    lead: "Agentische systemen vermenigvuldigen non-human identities razendsnel. HelixIAM geeft elke identiteit een echte identiteit, delegatie met minimale rechten en een kill-switch — zodat autonomie nooit verlies van controle betekent.",
    metaDesc: "HelixIAM voor AI- en platformteams: agent-identiteit, RFC 8693-delegatie, workload identity federation, governance via kill-switch.",
    rows: [
      { heading: "Elke agent, verantwoordelijk", icon: "agent", body: "Registreer agents als benoemde identiteiten met een eigenaar. Hun tokens zijn beperkt in scope, kortlevend en herleidbaar tot de mens voor wie ze handelen.", bullets: ["Agent-register & levenscyclus", "On-behalf-of tokens (sub + act)", "Scope-intersectie & beperking", "Vastleggen van toestemming"] },
      { heading: "Sleutelloze workloads", icon: "cloud", body: "Kubernetes en CI hebben al ondertekende identiteiten. Wissel ze in voor HelixIAM-tokens — geen langlevende secrets die kunnen lekken of geroteerd moeten worden.", bullets: ["K8s / CI JWT-uitwisseling", "Gebonden aan service-accountrollen", "Kortlevend, audience-gebonden", "Directe intrekking"] },
      { heading: "Beperk de impact", icon: "shield", body: "Gedelegeerde bevoegdheid kan alleen smaller worden. Begrens scope en levensduur, en trek een realm-brede kill-switch zodra een agent zich misdraagt.", bullets: ["Monotone scope-versmalling", "Realm-brede kill-switch", "NHI-inventaris & eigendom", "Auth klaar voor MCP"] },
    ],
    productLinks: [{ label: "AI-agents & NHI", href: "/product/ai-agents/" }, { label: "Workload identity", href: "/product/workload-identity/" }, { label: "Beveiliging & compliance", href: "/product/security/" }],
  },
  {
    slug: "public-sector",
    navLabel: "Overheid & gereguleerd",
    icon: "eu",
    eyebrow: "Overheid & gereguleerd",
    title: 'Europese eID\'s, <span class="grad-text">zonder het integratieproject</span>.',
    lead: "DigiD, eHerkenning en eIDAS zijn eersteklas brokers met de juiste betrouwbaarheidsniveaus. Deploy soeverein, brand elke realm en voldoe aan AVG en FAPI waar het telt.",
    metaDesc: "HelixIAM voor overheid en gereguleerde sectoren: DigiD, eHerkenning, eIDAS, betrouwbaarheidsniveaus, soevereiniteit en AVG.",
    rows: [
      { heading: "De eID's, ingebouwd", icon: "eu", body: "Burgers en bedrijven melden zich aan met inloggegevens die ze al vertrouwen — gebrokerd met de juiste betrouwbaarheidsniveaus, geen maatwerkintegratie.", bullets: ["DigiD (NL burger)", "eHerkenning (NL zakelijk)", "eIDAS (grensoverschrijdend EU)", "Handhaving van betrouwbaarheidsniveau"] },
      { heading: "Soeverein & gebrand", icon: "cloud", body: "Draai in je eigen of een nationale cloud, air-gap indien nodig, en geef elke realm een eigen thema — met Nederlandse lokalisatie direct beschikbaar.", bullets: ["Zelf te hosten, EU-dataresidentie", "Login-theming per realm", "nl-NL-lokalisatie", "Signeersleutels per realm"] },
      { heading: "Compliance die je kunt aantonen", icon: "shield", body: "Tokenbeveiliging op FAPI-niveau, een doorzoekbare auditlog en AVG-rechtentooling geven je het bewijs waar toezichthouders om vragen.", bullets: ["FAPI + DPoP + mTLS", "Doorzoekbare audit + SIEM", "AVG-rechtentooling", "Fijnmazige admin-RBAC"] },
    ],
    productLinks: [{ label: "Europese eID's", href: "/product/european-eid/" }, { label: "Beveiliging & compliance", href: "/product/security/" }, { label: "SSO & federatie", href: "/product/sso-federation/" }],
  },
];

export const solutionsFor = (locale: Locale): Solution[] => locale === "fr" ? SOLUTIONS_FR : locale === "nl" ? SOLUTIONS_NL : SOLUTIONS;
export const solutionFor = (slug: string, locale: Locale) => solutionsFor(locale).find((s) => s.slug === slug);
