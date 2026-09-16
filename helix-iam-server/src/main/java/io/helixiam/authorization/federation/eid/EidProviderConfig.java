/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

/**
 * Helix IAM E6: configuration for one EU/NL eID connector (eIDAS / eHerkenning / DigiD). Builds on
 * the SAML2 SP profile but adds the eID-specific material: an SP decryption key (the assertion — and
 * thus the BSN / PersonIdentifier — is encrypted to the SP), an SP signing key (DigiD/eHerkenning
 * require the AuthnRequest to be XML-signed), a minimum level of assurance, and the scheme attribute
 * that carries the subject identifier.
 *
 * @param scheme                      which government scheme this connector speaks
 * @param alias                       stable provider alias (registry key)
 * @param displayName                 label for the login page / admin console
 * @param ssoUrl                      the IdP/broker SSO endpoint
 * @param idpEntityId                 the IdP/broker entity id (expected assertion issuer)
 * @param spEntityId                  Helix's SP entity id (the AuthnRequest issuer + assertion audience)
 * @param assertionConsumerServiceUrl Helix's ACS URL the IdP posts the Response back to
 * @param idpSigningCertificate       the IdP's signing certificate (PEM) for assertion verification
 * @param spDecryptionPrivateKey      the SP's private key (PEM, PKCS#8) used to decrypt the assertion
 * @param spSigningPrivateKey         the SP's private key (PEM, PKCS#8) used to sign the AuthnRequest
 * @param spSigningCertificate        the SP's certificate (PEM) embedded in the signed AuthnRequest
 * @param minimumLoa                  minimum AuthnContextClassRef URN to accept (blank = any)
 * @param subjectAttribute            assertion attribute carrying the subject id (BSN / PersonIdentifier / entityConcernedID)
 * @param authnRequestBinding         how the AuthnRequest is sent: POST + enveloped XML signature
 *                                    (CombiConnect / eID-stelsel / eHerkenning / eIDAS) or REDIRECT +
 *                                    detached query signature (classic DigiD SAML v3.x)
 * @param responseBinding             how the assertion comes back: {@link ResponseBinding#POST} (the IdP
 *                                    POSTs a signed+encrypted SAMLResponse to the ACS — modern
 *                                    CombiConnect / eID-stelsel / eHerkenning / eIDAS) or
 *                                    {@link ResponseBinding#ARTIFACT} (classic DigiD "Koppelvlak SAML":
 *                                    the IdP returns a {@code SAMLart} on the front channel and Helix
 *                                    resolves the signed assertion over the SOAP back-channel)
 * @param artifactResolutionServiceUrl the IdP's Artifact Resolution Service (ARS) endpoint — required
 *                                    when {@code responseBinding == ARTIFACT}; the signed
 *                                    {@code ArtifactResolve} is POSTed here over (mutually-authenticated) TLS
 */
public record EidProviderConfig(EidScheme scheme, String alias, String displayName, String ssoUrl,
                                String idpEntityId, String spEntityId, String assertionConsumerServiceUrl,
                                String idpSigningCertificate, String spDecryptionPrivateKey,
                                String spSigningPrivateKey, String spSigningCertificate,
                                String minimumLoa, String subjectAttribute, Binding authnRequestBinding,
                                Representation representation, ResponseBinding responseBinding,
                                String artifactResolutionServiceUrl, String singleLogoutServiceUrl) {

    /** SAML AuthnRequest binding for the start of the flow. */
    public enum Binding { POST, REDIRECT }

    /**
     * How the IdP returns the assertion. {@code POST} = front-channel signed+encrypted SAMLResponse to
     * the ACS (modern eID). {@code ARTIFACT} = front-channel {@code SAMLart} + back-channel SOAP
     * {@code ArtifactResolve}/{@code ArtifactResponse} to the ARS (classic DigiD Koppelvlak SAML).
     */
    public enum ResponseBinding { POST, ARTIFACT }

    /**
     * DigiD Machtigen / eHerkenning representation (mandate) configuration — opt-in. The exact
     * attribute identifiers are deployment/version-specific (operator supplies them from the DigiD
     * Machtigen / eHerkenning onboarding), so they are configured rather than hard-coded.
     *
     * @param requested             whether the AuthnRequest asks for representation, mandated for serviceId
     * @param serviceId             the service the mandate applies to (carried in the request when requested)
     * @param actingSubjectAttribute the assertion attribute holding the acting subject (the representative)
     * @param serviceIdAttribute    the assertion attribute holding the asserted service id (may be null)
     */
    public record Representation(boolean requested, String serviceId, String actingSubjectAttribute,
                                 String serviceIdAttribute) {
    }

    /** Defaults null bindings to POST (the modern CombiConnect/eID-stelsel/eHerkenning/eIDAS default). */
    public EidProviderConfig {
        authnRequestBinding = authnRequestBinding == null ? Binding.POST : authnRequestBinding;
        responseBinding = responseBinding == null ? ResponseBinding.POST : responseBinding;
    }

    /** Back-compat: full config minus the upstream SLO endpoint (federated logout becomes a no-op). */
    public EidProviderConfig(final EidScheme scheme, final String alias, final String displayName, final String ssoUrl,
                             final String idpEntityId, final String spEntityId, final String assertionConsumerServiceUrl,
                             final String idpSigningCertificate, final String spDecryptionPrivateKey,
                             final String spSigningPrivateKey, final String spSigningCertificate,
                             final String minimumLoa, final String subjectAttribute, final Binding authnRequestBinding,
                             final Representation representation, final ResponseBinding responseBinding,
                             final String artifactResolutionServiceUrl) {
        this(scheme, alias, displayName, ssoUrl, idpEntityId, spEntityId, assertionConsumerServiceUrl,
                idpSigningCertificate, spDecryptionPrivateKey, spSigningPrivateKey, spSigningCertificate,
                minimumLoa, subjectAttribute, authnRequestBinding, representation, responseBinding,
                artifactResolutionServiceUrl, null);
    }

    /** Convenience: an explicit AuthnRequest binding + representation, default front-channel POST response. */
    public EidProviderConfig(final EidScheme scheme, final String alias, final String displayName, final String ssoUrl,
                             final String idpEntityId, final String spEntityId, final String assertionConsumerServiceUrl,
                             final String idpSigningCertificate, final String spDecryptionPrivateKey,
                             final String spSigningPrivateKey, final String spSigningCertificate,
                             final String minimumLoa, final String subjectAttribute, final Binding authnRequestBinding,
                             final Representation representation) {
        this(scheme, alias, displayName, ssoUrl, idpEntityId, spEntityId, assertionConsumerServiceUrl,
                idpSigningCertificate, spDecryptionPrivateKey, spSigningPrivateKey, spSigningCertificate,
                minimumLoa, subjectAttribute, authnRequestBinding, representation, ResponseBinding.POST, null);
    }

    /** Convenience: a provider with an explicit binding but no representation. */
    public EidProviderConfig(final EidScheme scheme, final String alias, final String displayName, final String ssoUrl,
                             final String idpEntityId, final String spEntityId, final String assertionConsumerServiceUrl,
                             final String idpSigningCertificate, final String spDecryptionPrivateKey,
                             final String spSigningPrivateKey, final String spSigningCertificate,
                             final String minimumLoa, final String subjectAttribute, final Binding authnRequestBinding) {
        this(scheme, alias, displayName, ssoUrl, idpEntityId, spEntityId, assertionConsumerServiceUrl,
                idpSigningCertificate, spDecryptionPrivateKey, spSigningPrivateKey, spSigningCertificate,
                minimumLoa, subjectAttribute, authnRequestBinding, null, ResponseBinding.POST, null);
    }

    /** Convenience: a provider on the default POST binding, no representation. */
    public EidProviderConfig(final EidScheme scheme, final String alias, final String displayName, final String ssoUrl,
                             final String idpEntityId, final String spEntityId, final String assertionConsumerServiceUrl,
                             final String idpSigningCertificate, final String spDecryptionPrivateKey,
                             final String spSigningPrivateKey, final String spSigningCertificate,
                             final String minimumLoa, final String subjectAttribute) {
        this(scheme, alias, displayName, ssoUrl, idpEntityId, spEntityId, assertionConsumerServiceUrl,
                idpSigningCertificate, spDecryptionPrivateKey, spSigningPrivateKey, spSigningCertificate,
                minimumLoa, subjectAttribute, Binding.POST, null, ResponseBinding.POST, null);
    }
}
