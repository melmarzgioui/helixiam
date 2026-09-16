package group.mfnr.authorization.federation.oidc;

import java.util.List;

/**
 * Helix IAM E5.2: configuration for one external OIDC identity provider (or a social preset). The
 * endpoints come from the provider's discovery document; the client credentials are issued by that
 * provider for Helix as a relying party.
 *
 * @param alias                  stable provider alias (the registry key + the URL segment)
 * @param displayName            label for the login page / admin console
 * @param clientId               Helix's client id at the external provider
 * @param clientSecret           Helix's client secret (confidential client)
 * @param authorizationEndpoint  the provider's authorize endpoint
 * @param tokenEndpoint          the provider's token endpoint
 * @param jwksUri                the provider's JWKS endpoint (ID-token signature verification)
 * @param issuer                 the expected ID-token issuer
 * @param scopes                 scopes to request (must include "openid")
 * @param endSessionEndpoint     the provider's RP-initiated logout endpoint ({@code null} = upstream SLO off)
 */
public record OidcProviderConfig(String alias, String displayName, String clientId, String clientSecret,
                                 String authorizationEndpoint, String tokenEndpoint, String jwksUri,
                                 String issuer, List<String> scopes, String endSessionEndpoint) {

    /** Back-compat constructor for providers configured without an {@code end_session_endpoint}. */
    public OidcProviderConfig(final String alias, final String displayName, final String clientId,
                              final String clientSecret, final String authorizationEndpoint, final String tokenEndpoint,
                              final String jwksUri, final String issuer, final List<String> scopes) {
        this(alias, displayName, clientId, clientSecret, authorizationEndpoint, tokenEndpoint, jwksUri, issuer,
                scopes, null);
    }

    public String scopeParam() {
        return scopes == null || scopes.isEmpty() ? "openid" : String.join(" ", scopes);
    }
}
