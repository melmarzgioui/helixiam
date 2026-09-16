/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A SAML 2.0 relying party (service provider) from the SAML-clients admin API. */
export interface SamlClient {
  realmId: string;
  entityId: string;
  assertionConsumerServiceUrl: string;
  defaultAuthnContextClassRef: string | null;
  singleLogoutServiceUrl: string | null;
  /** The SP's signing cert (PEM) — used to validate the SP's signed LogoutRequests; null = not enforced. */
  signingCertificate: string | null;
  enabled: boolean;
  /** The parent Application (`realmId|name`) this SP hangs below; `null` = standalone RP. */
  applicationId: string | null;
  /** WSO2-class advanced SAML options; null fields = IdP default. */
  options?: SamlSpOptions | null;
}

/** WSO2-class advanced per-SP SAML2 options. All nullable — null = the IdP default. */
export interface SamlSpOptions {
  signAssertion?: boolean | null;
  signResponse?: boolean | null;
  wantAuthnRequestsSigned?: boolean | null;
  wantLogoutRequestsSigned?: boolean | null;
  encryptAssertion?: boolean | null;
  encryptionCertificate?: string | null;
  signatureAlgorithm?: string | null;
  digestAlgorithm?: string | null;
  nameIdFormat?: string | null;
  includeAttributes?: boolean | null;
  additionalAcsUrls?: string[] | null;
  extraAudiences?: string[] | null;
  extraRecipients?: string[] | null;
  backChannelSloEnabled?: boolean | null;
  idpInitiatedSsoEnabled?: boolean | null;
  assertionLifetimeSeconds?: number | null;
}

export interface SamlClientWrite {
  entityId: string;
  assertionConsumerServiceUrl: string;
  defaultAuthnContextClassRef?: string | null;
  singleLogoutServiceUrl?: string | null;
  signingCertificate?: string | null;
  enabled?: boolean;
  /** The parent Application (`realmId|name`); send the existing value to preserve the link on save. */
  applicationId?: string | null;
  options?: SamlSpOptions | null;
}

export interface SamlClientApi {
  list(realmId: string): Promise<SamlClient[]>;
  create(realmId: string, body: SamlClientWrite): Promise<SamlClient>;
  update(realmId: string, entityId: string, body: SamlClientWrite): Promise<SamlClient>;
  remove(realmId: string, entityId: string): Promise<void>;
  /** WSO2-class onboarding: parse an uploaded SP metadata XML into a pre-filled relying-party write. */
  importMetadata(realmId: string, metadataXml: string): Promise<SamlClientWrite>;
  /** Fetch an SP's metadata from its published URL (server-side) and pre-fill. */
  importMetadataUrl(realmId: string, metadataUrl: string): Promise<SamlClientWrite>;
}

/** The realm-level SAML IdP metadata descriptor URL (the SAML twin of the OIDC discovery endpoint). */
export function samlIdpMetadataUrl(baseUrl: string, realmId: string): string {
  return `${baseUrl.replace(/\/$/, "")}/realms/${encodeURIComponent(realmId)}/saml/idp/metadata`;
}

/** Field-level validation for the SAML relying-party form. Pure so it can be unit-tested. */
export function validateSamlClient(w: SamlClientWrite): Record<string, string> {
  const errors: Record<string, string> = {};
  const isHttpUrl = (s: string) => /^https?:\/\/.+/i.test(s.trim());
  if (!w.entityId?.trim()) {
    errors.entityId = "Entity ID is required.";
  }
  if (!w.assertionConsumerServiceUrl?.trim()) {
    errors.assertionConsumerServiceUrl = "ACS URL is required.";
  } else if (!isHttpUrl(w.assertionConsumerServiceUrl)) {
    errors.assertionConsumerServiceUrl = "Must be an http(s) URL.";
  }
  if (w.singleLogoutServiceUrl && w.singleLogoutServiceUrl.trim() && !isHttpUrl(w.singleLogoutServiceUrl)) {
    errors.singleLogoutServiceUrl = "Must be an http(s) URL.";
  }
  const o = w.options;
  if (o) {
    if (o.encryptAssertion && !o.encryptionCertificate?.trim()) {
      errors.encryptionCertificate = "An encryption certificate is required to encrypt assertions.";
    }
    if (o.additionalAcsUrls?.some((u) => u.trim() && !isHttpUrl(u))) {
      errors.additionalAcsUrls = "Each additional ACS URL must be an http(s) URL.";
    }
    if (o.extraRecipients?.some((u) => u.trim() && !isHttpUrl(u))) {
      errors.extraRecipients = "Each recipient must be an http(s) URL.";
    }
  }
  return errors;
}

/** HTTP-backed client for the SAML relying-party admin REST API. */
export function createSamlClientHttpClient(baseUrl = ""): SamlClientApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, entityId?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/saml-clients${
      entityId ? `/${encodeURIComponent(entityId)}` : ""
    }`;

  const json = async (res: Response) => {
    if (!res.ok) {
      // Surface the backend's reason (Spring puts it in `message`/`error`) instead of a bare status code.
      let detail = "";
      try {
        const body = await res.clone().json();
        detail = body?.message || body?.error || "";
      } catch { /* non-JSON error body */ }
      throw new Error(detail || `${res.status} ${res.statusText || "request failed"}`);
    }
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId) => fetch(url(realmId)).then(json),
    create: (realmId, body) =>
      fetch(url(realmId), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(json),
    update: (realmId, entityId, body) =>
      fetch(url(realmId, entityId), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(json),
    remove: (realmId, entityId) =>
      fetch(url(realmId, entityId), { method: "DELETE" })
        .then(json)
        .then(() => undefined),
    importMetadata: (realmId, metadataXml) =>
      fetch(`${url(realmId)}/import`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ metadataXml }),
      }).then(json),
    importMetadataUrl: (realmId, metadataUrl) =>
      fetch(`${url(realmId)}/import-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: metadataUrl }),
      }).then(json),
  };
}
