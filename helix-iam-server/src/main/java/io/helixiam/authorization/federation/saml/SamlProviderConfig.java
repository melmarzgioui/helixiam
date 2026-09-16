package io.helixiam.authorization.federation.saml;

/**
 * Helix IAM E5.2: configuration for an external SAML2 IdP that Helix consumes as a Service Provider.
 *
 * @param alias                       stable provider alias (registry key)
 * @param displayName                 label for the login page / admin console
 * @param ssoUrl                      the IdP's SSO endpoint (where the AuthnRequest is sent)
 * @param idpEntityId                 the IdP's entity id (expected assertion issuer)
 * @param spEntityId                  Helix's SP entity id (the AuthnRequest issuer)
 * @param assertionConsumerServiceUrl Helix's ACS URL the IdP posts the Response back to
 * @param idpSigningCertificate       the IdP's signing certificate (PEM) for assertion verification
 * @param emailAttribute              assertion attribute holding the email
 * @param firstNameAttribute          assertion attribute holding the given name
 * @param lastNameAttribute           assertion attribute holding the surname
 * @param singleLogoutServiceUrl      the IdP's SLO endpoint — when set, federated logout sends a
 *                                    {@code <LogoutRequest>} here (HTTP-Redirect, best-effort); null = no SLO
 */
public record SamlProviderConfig(String alias, String displayName, String ssoUrl, String idpEntityId,
                                 String spEntityId, String assertionConsumerServiceUrl, String idpSigningCertificate,
                                 String emailAttribute, String firstNameAttribute, String lastNameAttribute,
                                 String singleLogoutServiceUrl) {

    /** Back-compat: a provider without a configured SLO endpoint (federated logout becomes a no-op). */
    public SamlProviderConfig(final String alias, final String displayName, final String ssoUrl, final String idpEntityId,
                              final String spEntityId, final String assertionConsumerServiceUrl, final String idpSigningCertificate,
                              final String emailAttribute, final String firstNameAttribute, final String lastNameAttribute) {
        this(alias, displayName, ssoUrl, idpEntityId, spEntityId, assertionConsumerServiceUrl, idpSigningCertificate,
                emailAttribute, firstNameAttribute, lastNameAttribute, null);
    }
}
