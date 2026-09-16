// Single source of truth for site metadata, navigation, and real product facts.
// No invented customers/quotes — capability claims map 1:1 to the shipped product + docs.
import type { Locale } from "./i18n";

export const SITE = {
  name: "HelixIAM",
  parent: "KubeDNA",
  domain: "helixiam.com",
  url: "https://helixiam.com",
  docsUrl: "https://docs.helixiam.com",
  tagline: "Identity, in your DNA.",
  description:
    "HelixIAM is the European identity fabric for humans, AI agents, and workloads. Keycloak-class SSO, MFA and federation — plus first-class non-human identity, workload identity federation, and EU eIDs. A KubeDNA product.",
  demoPath: "/demo/",
  contactPath: "/contact/",
  email: "hello@helixiam.com",
};

export type NavChild = { label: string; href: string; blurb?: string };
export type NavItem = { label: string; href: string; children?: NavChild[] };

export const NAV: NavItem[] = [
  {
    label: "Product",
    href: "/product/",
    children: [
      { label: "Platform overview", href: "/product/", blurb: "One identity fabric for every subject." },
      { label: "Authentication & MFA", href: "/product/authentication/", blurb: "Passkeys, OTP, device push, adaptive." },
      { label: "SSO & Federation", href: "/product/sso-federation/", blurb: "OIDC, SAML, social, LDAP/AD brokers." },
      { label: "AI Agents & NHI", href: "/product/ai-agents/", blurb: "Identity & delegation for AI agents." },
      { label: "Workload Identity", href: "/product/workload-identity/", blurb: "Keyless K8s/CI token exchange." },
      { label: "European eIDs", href: "/product/european-eid/", blurb: "eIDAS, eHerkenning, DigiD built in." },
      { label: "Developer experience", href: "/product/developers/", blurb: "SDKs, Terraform, config-as-code." },
      { label: "Security & Compliance", href: "/product/security/", blurb: "FAPI, DPoP, per-realm keys, audit." },
    ],
  },
  {
    label: "Solutions",
    href: "/solutions/",
    children: [
      { label: "For developers", href: "/solutions/developers/", blurb: "Ship login in an afternoon." },
      { label: "For security & CISOs", href: "/solutions/security-teams/", blurb: "Provable control, EU sovereignty." },
      { label: "For AI & platform teams", href: "/solutions/ai-teams/", blurb: "Govern every agent and workload." },
      { label: "Public sector & regulated", href: "/solutions/public-sector/", blurb: "eIDAS, DigiD, eHerkenning, FAPI." },
    ],
  },
  { label: "Why HelixIAM", href: "/why-helixiam/" },
  { label: "Docs", href: SITE.docsUrl },
  {
    label: "Company",
    href: "/company/",
    children: [
      { label: "About", href: "/company/", blurb: "European identity, engineered by KubeDNA." },
      { label: "Trust & security", href: "/trust/", blurb: "How we protect identity." },
      { label: "Blog", href: "/blog/", blurb: "Notes on the identity fabric." },
      { label: "Contact", href: "/contact/", blurb: "Talk to the team." },
    ],
  },
];

// The two strands of the helix — the product's core metaphor + differentiator.
export const STRANDS = [
  {
    key: "human",
    title: "Human identity",
    blurb:
      "Passwordless passkeys, adaptive MFA, SSO and federation for every person — employees, customers, and citizens.",
    points: ["Passkeys & WebAuthn", "Adaptive, risk-based MFA", "OIDC · SAML · social · LDAP", "EU eIDs out of the box"],
  },
  {
    key: "nonhuman",
    title: "Non-human identity",
    blurb:
      "First-class identity for AI agents and workloads — scoped tokens, on-behalf-of delegation, and keyless federation.",
    points: ["AI-agent identities", "RFC 8693 delegation (act-as)", "Workload Identity Federation", "Attenuated, kill-switchable"],
  },
];

// Headline differentiators used on the home hero + why page.
export const DIFFERENTIATORS = [
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
];

// Capability grid — every item is shipped and documented.
export const CAPABILITIES = [
  { group: "Authentication", items: ["Passkeys / WebAuthn (FIDO2)", "TOTP, SMS-OTP, Email-OTP, HOTP", "Device push + mobile SDK", "Magic-link passwordless", "Recovery codes", "Risk-based / adaptive step-up"] },
  { group: "SSO & Federation", items: ["OpenID Connect provider", "SAML 2.0 IdP & SP", "Social & OIDC brokers", "LDAP / Active Directory", "JIT provisioning + account linking", "Single Logout (front, back, SAML)"] },
  { group: "Non-human identity", items: ["AI-agent registry & lifecycle", "RFC 8693 token exchange (act-as)", "Workload Identity Federation", "Scoped & attenuated tokens", "Consent + kill-switch", "MCP-ready auth (OAuth 2.1)"] },
  { group: "European eIDs", items: ["eIDAS (EU cross-border)", "eHerkenning (NL business)", "DigiD (NL citizen)", "Assurance levels", "Per-realm branding", "NL-i18n"] },
  { group: "Developer & admin", items: ["Keycloak-class admin console", "TypeScript SDK + adapters", "Terraform provider (IaC)", "Config-as-code (import/export)", "Keycloak importer", "OpenAPI + SCIM 2.0"] },
  { group: "Security & compliance", items: ["FAPI + mTLS-bound tokens", "DPoP (RFC 9449)", "Per-realm KMS keys + rotation", "Searchable audit log + SIEM", "GDPR rights tooling", "Brute-force + password policy"] },
];

// Localized capability-group headers (the bullet items are protocol/standard identifiers → kept as-is).
const CAP_GROUPS: Record<Locale, string[]> = {
  en: ["Authentication", "SSO & Federation", "Non-human identity", "European eIDs", "Developer & admin", "Security & compliance"],
  fr: ["Authentification", "SSO & Fédération", "Identité non humaine", "eID européens", "Développeur & admin", "Sécurité & conformité"],
  nl: ["Authenticatie", "SSO & Federatie", "Non-human identity", "Europese eID's", "Ontwikkelaar & admin", "Beveiliging & compliance"],
};

/** Capabilities with the group header translated for the given locale (items unchanged). */
export const capabilitiesFor = (locale: Locale) =>
  CAPABILITIES.map((c, i) => ({ group: CAP_GROUPS[locale]?.[i] ?? c.group, items: c.items }));

export const STATS = [
  { value: "3", label: "identity subjects", sub: "humans · agents · workloads" },
  { value: "9", label: "auth factors", sub: "passkeys to device push" },
  { value: "100%", label: "open standards", sub: "no proprietary lock-in" },
  { value: "EU", label: "sovereign by design", sub: "your keys, your realm" },
];
