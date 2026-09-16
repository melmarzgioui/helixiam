import type { Locale } from "../i18n";

export interface PracticeCard {
  t: string;
  i: string;
  items: string[];
}

export interface TrustStr {
  metaTitle: string;
  metaDesc: string;
  eyebrow: string;
  title: string;
  lead: string;
  practices: PracticeCard[];
  roadmapChip: string;
  roadmapBody: string;
  roadmapCta: string;
  ctaTitle: string;
  ctaSub: string;
}

export const trust: Record<Locale, TrustStr> = {
  en: {
    metaTitle: "Trust & security",
    metaDesc:
      "How HelixIAM protects identity: per-realm keys, FAPI/DPoP, EU sovereignty, searchable audit and GDPR tooling.",
    eyebrow: "Trust center",
    title: 'Security you can <span class="grad-text">inspect and prove</span>.',
    lead: "Identity is the front door to everything. Here's exactly how HelixIAM is built to protect it — the controls, the standards, and the sovereignty guarantees.",
    practices: [
      { t: "Cryptography you control", i: "key", items: ["Per-realm signing keys (KMS / HSM / PKCS#11)", "Zero-downtime key rotation", "Argon2id password hashing", "Keys generated and held where you run"] },
      { t: "Token security", i: "shield", items: ["FAPI client policies", "DPoP sender-constrained tokens (RFC 9449)", "mTLS certificate-bound tokens", "PKCE + short-lived, audience-bound tokens"] },
      { t: "Data & sovereignty", i: "eu", items: ["Self-hostable — your cloud, on-prem, air-gapped", "EU data residency", "No third-party control plane", "GDPR rights tooling built in"] },
      { t: "Auditability", i: "eye", items: ["Persisted, searchable audit log", "SIEM streaming (HTTP forwarder)", "HMAC-signed outbound webhooks", "Full admin-impersonation trail"] },
      { t: "Access governance", i: "users", items: ["Fine-grained admin RBAC", "Brute-force protection & lockout", "Password policy + breached-password checks", "Concurrent-session limits"] },
      { t: "Standards & interop", i: "protocol", items: ["OAuth 2.1 / OIDC / SAML 2.0", "WebAuthn / FIDO2 passkeys", "RFC 8693, RFC 8707, RFC 8628", "SCIM 2.0 provisioning"] },
    ],
    roadmapChip: "Certification roadmap",
    roadmapBody:
      "HelixIAM is built to satisfy FAPI-grade requirements and NL/EU eID assurance. Formal third-party attestations — OpenID Certified & FAPI conformance, SOC 2 / ISO 27001, independent penetration testing and signed releases — are on our roadmap. We'll publish them here as they land, and we're happy to share our current posture, SBOM, and security questionnaire under NDA.",
    roadmapCta: "Request our security pack",
    ctaTitle: "Put it under the microscope.",
    ctaSub:
      "Bring your security questionnaire, your architecture, and your hardest questions. We'll walk through the controls on a live system.",
  },
  fr: {
    metaTitle: "Confiance & sécurité",
    metaDesc:
      "Comment HelixIAM protège l'identité : clés par realm, FAPI/DPoP, souveraineté européenne, journal d'audit consultable et outils RGPD.",
    eyebrow: "Centre de confiance",
    title: 'Une sécurité que vous pouvez <span class="grad-text">inspecter et prouver</span>.',
    lead: "L'identité est la porte d'entrée de tout. Voici précisément comment HelixIAM est conçu pour la protéger — les contrôles, les standards et les garanties de souveraineté.",
    practices: [
      { t: "Une cryptographie que vous contrôlez", i: "key", items: ["Clés de signature par realm (KMS / HSM / PKCS#11)", "Rotation des clés sans temps d'arrêt", "Hachage des mots de passe Argon2id", "Clés générées et détenues là où vous exécutez"] },
      { t: "Sécurité des tokens", i: "shield", items: ["Politiques client FAPI", "Tokens liés à l'émetteur DPoP (RFC 9449)", "Tokens liés au certificat mTLS", "PKCE + tokens de courte durée, liés à l'audience"] },
      { t: "Données & souveraineté", i: "eu", items: ["Auto-hébergeable — votre cloud, on-prem, isolé du réseau", "Résidence des données dans l'UE", "Aucun plan de contrôle tiers", "Outils de droits RGPD intégrés"] },
      { t: "Auditabilité", i: "eye", items: ["Journal d'audit persistant et consultable", "Streaming vers SIEM (transitaire HTTP)", "Webhooks sortants signés HMAC", "Traçabilité complète de l'usurpation admin"] },
      { t: "Gouvernance des accès", i: "users", items: ["RBAC admin à granularité fine", "Protection anti-force brute & verrouillage", "Politique de mot de passe + vérification des mots de passe compromis", "Limites de sessions simultanées"] },
      { t: "Standards & interopérabilité", i: "protocol", items: ["OAuth 2.1 / OIDC / SAML 2.0", "Passkeys WebAuthn / FIDO2", "RFC 8693, RFC 8707, RFC 8628", "Provisionnement SCIM 2.0"] },
    ],
    roadmapChip: "Feuille de route des certifications",
    roadmapBody:
      "HelixIAM est conçu pour satisfaire les exigences de niveau FAPI et l'assurance des eID NL/UE. Les attestations formelles de tiers — conformité OpenID Certified & FAPI, SOC 2 / ISO 27001, tests d'intrusion indépendants et versions signées — figurent sur notre feuille de route. Nous les publierons ici au fur et à mesure, et nous sommes heureux de partager notre posture actuelle, notre SBOM et notre questionnaire de sécurité sous NDA.",
    roadmapCta: "Demander notre dossier de sécurité",
    ctaTitle: "Passez-le au microscope.",
    ctaSub:
      "Apportez votre questionnaire de sécurité, votre architecture et vos questions les plus difficiles. Nous parcourrons les contrôles sur un système en direct.",
  },
  nl: {
    metaTitle: "Vertrouwen & beveiliging",
    metaDesc:
      "Hoe HelixIAM identiteit beschermt: sleutels per realm, FAPI/DPoP, EU-soevereiniteit, doorzoekbare auditlog en AVG-tooling.",
    eyebrow: "Vertrouwenscentrum",
    title: 'Beveiliging die je kunt <span class="grad-text">inspecteren en bewijzen</span>.',
    lead: "Identiteit is de voordeur naar alles. Hier lees je precies hoe HelixIAM is gebouwd om die te beschermen — de controls, de standaarden en de soevereiniteitsgaranties.",
    practices: [
      { t: "Cryptografie die jij beheert", i: "key", items: ["Ondertekeningssleutels per realm (KMS / HSM / PKCS#11)", "Sleutelrotatie zonder downtime", "Argon2id-wachtwoordhashing", "Sleutels gegenereerd en bewaard waar jij draait"] },
      { t: "Tokenbeveiliging", i: "shield", items: ["FAPI-clientbeleid", "DPoP sender-constrained tokens (RFC 9449)", "mTLS-certificaatgebonden tokens", "PKCE + kortlevende, audience-gebonden tokens"] },
      { t: "Data & soevereiniteit", i: "eu", items: ["Zelf te hosten — je cloud, on-prem, air-gapped", "EU-dataresidentie", "Geen control plane van derden", "AVG-rechtentooling ingebouwd"] },
      { t: "Auditbaarheid", i: "eye", items: ["Persistente, doorzoekbare auditlog", "SIEM-streaming (HTTP-forwarder)", "HMAC-ondertekende uitgaande webhooks", "Volledig spoor van admin-impersonatie"] },
      { t: "Toegangsgovernance", i: "users", items: ["Fijnmazige admin-RBAC", "Brute-force-bescherming & lockout", "Wachtwoordbeleid + controle op gelekte wachtwoorden", "Limieten op gelijktijdige sessies"] },
      { t: "Standaarden & interop", i: "protocol", items: ["OAuth 2.1 / OIDC / SAML 2.0", "WebAuthn / FIDO2 passkeys", "RFC 8693, RFC 8707, RFC 8628", "SCIM 2.0-provisioning"] },
    ],
    roadmapChip: "Certificeringsroadmap",
    roadmapBody:
      "HelixIAM is gebouwd om te voldoen aan FAPI-eisen en NL/EU-eID-assurance. Formele attesten van derden — OpenID Certified- & FAPI-conformiteit, SOC 2 / ISO 27001, onafhankelijke penetratietests en ondertekende releases — staan op onze roadmap. We publiceren ze hier zodra ze er zijn, en we delen graag onze huidige posture, SBOM en beveiligingsvragenlijst onder NDA.",
    roadmapCta: "Vraag ons beveiligingspakket aan",
    ctaTitle: "Leg het onder de microscoop.",
    ctaSub:
      "Neem je beveiligingsvragenlijst, je architectuur en je lastigste vragen mee. We lopen de controls door op een live systeem.",
  },
};
