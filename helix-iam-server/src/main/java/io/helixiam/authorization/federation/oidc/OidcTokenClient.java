package io.helixiam.authorization.federation.oidc;

import java.util.Map;

/**
 * Helix IAM E5.2: the back-channel token exchange seam for the OIDC broker. Implementations POST the
 * authorization code to the provider's token endpoint (TLS, confidential client) and return the
 * validated ID-token claims. Behind a seam so {@link OidcIdentityProvider}'s redirect-building +
 * claim-mapping + state/nonce checks are unit-testable without network.
 */
public interface OidcTokenClient {

    /** Exchange the code at the provider's token endpoint; returns the ID-token claims + access token. */
    OidcTokens exchange(OidcProviderConfig config, String code, String redirectUri);

    /** The token-endpoint result: ID-token claims (incl. sub/email/nonce) and the raw access token. */
    record OidcTokens(Map<String, Object> idTokenClaims, String accessToken) {
    }
}
