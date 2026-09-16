/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { SAML } from '@node-saml/node-saml';

// SAML2 Service Provider wiring for the sandbox. The SP consumes the Helix IdP metadata to discover
// the entityID, SSO/SLO endpoints and signing certificate, then builds a node-saml instance. The SP
// itself is registered with the IdP dynamically via the admin API / console (no static config).

const PEM_CERT = (body) =>
  `-----BEGIN CERTIFICATE-----\n${body.replace(/\s+/g, '').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;

/** Pull the bits an SP needs out of the IdP's SAML metadata XML. */
export function parseIdpMetadata(xml) {
  const entityId = (xml.match(/entityID="([^"]+)"/) || [])[1];
  const cert = (xml.match(/<ds:X509Certificate>([\s\S]*?)<\/ds:X509Certificate>/) || [])[1];
  // Prefer the HTTP-Redirect binding for SSO (we send the AuthnRequest as a redirect).
  const ssoRedirect = (xml.match(
    /<md:SingleSignOnService[^>]*HTTP-Redirect[^>]*Location="([^"]+)"/,
  ) || [])[1];
  const sloRedirect = (xml.match(
    /<md:SingleLogoutService[^>]*HTTP-Redirect[^>]*Location="([^"]+)"/,
  ) || [])[1];
  if (!entityId || !cert || !ssoRedirect) {
    throw new Error('IdP metadata missing entityID / certificate / SSO endpoint');
  }
  return { entityId, cert: cert.trim(), ssoUrl: ssoRedirect, sloUrl: sloRedirect };
}

/**
 * Build the SP. `cfg` carries spEntityId, acsUrl, sloUrl and the fetched IdP metadata.
 * Returns the node-saml instance plus the resolved IdP descriptor (for display).
 */
export async function buildSamlSp(cfg, fetchImpl = fetch) {
  const res = await fetchImpl(cfg.idpMetadataUrl);
  if (!res.ok) throw new Error(`IdP metadata fetch failed: HTTP ${res.status}`);
  const xml = await res.text();
  const idp = parseIdpMetadata(xml);

  const saml = new SAML({
    // SP identity
    issuer: cfg.spEntityId,
    callbackUrl: cfg.acsUrl,
    logoutCallbackUrl: cfg.sloUrl,
    // IdP endpoints + trust
    entryPoint: idp.ssoUrl,
    logoutUrl: idp.sloUrl || idp.ssoUrl,
    idpCert: PEM_CERT(idp.cert),
    // The IdP issues a persistent NameID and signs the assertion (not the response).
    identifierFormat: null,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    signatureAlgorithm: 'sha256',
    // Stateless demo SP: don't require an InResponseTo cache.
    validateInResponseTo: 'never',
    acceptedClockSkewMs: 5000,
    disableRequestedAuthnContext: true,
  });

  return { saml, idp };
}
