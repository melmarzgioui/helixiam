package group.mfnr.authorization.idp.oidc;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 * Helix IAM E7.3/E7.4/E7.6: client-policy presets for the advanced-OIDC features. The protocol
 * mechanics are provided by Spring Authorization Server 1.5.x at runtime and advertised in the OIDC
 * discovery document — <b>PAR</b> (pushed authorization requests) and <b>DPoP</b> proof validation
 * (sender-constrained tokens) are server endpoints/automatic, and <b>Token Exchange</b> (RFC 8693) is
 * a grant type. Helix's job is to register clients with the right policy; these factories produce the
 * correct {@link RegisteredClient} for each profile.
 *
 * <ul>
 *   <li>{@link #tokenExchangeClient} — a service client allowed the RFC 8693 token-exchange grant.</li>
 *   <li>{@link #fapiClient} — a financial-grade client: {@code private_key_jwt} auth, mandatory PKCE,
 *       authorization-code only, short-lived non-reused tokens. Combined with the server's PAR + DPoP
 *       support this gives FAPI 2.0 sender-constrained, PAR-required behaviour.</li>
 *   <li>{@link #confidentialClient} — a standard confidential web client.</li>
 * </ul>
 */
public final class HelixClientPolicies {

    private HelixClientPolicies() {
    }

    /** A standard confidential authorization-code client. */
    public static RegisteredClient confidentialClient(final String clientId, final String clientSecret,
                                                      final String redirectUri, final String... scopes) {
        final RegisteredClient.Builder builder = baseAuthCode(clientId, redirectUri, scopes)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientSettings.builder().requireProofKey(false).requireAuthorizationConsent(true).build());
        return builder.build();
    }

    /** RFC 8693 token-exchange service client (impersonation/delegation between APIs). */
    public static RegisteredClient tokenExchangeClient(final String clientId, final String clientSecret) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scope("api.read")
                .build();
    }

    /**
     * Financial-grade (FAPI) client: {@code private_key_jwt} authentication, mandatory PKCE,
     * authorization-code only, short access tokens that are never reused. PAR + DPoP sender-constraining
     * are enforced by the server for such clients.
     */
    public static RegisteredClient fapiClient(final String clientId, final String jwkSetUrl,
                                              final String redirectUri, final String... scopes) {
        return baseAuthCode(clientId, redirectUri, scopes)
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)                 // PKCE mandatory (FAPI)
                        .requireAuthorizationConsent(true)
                        .jwkSetUrl(jwkSetUrl)                  // client's keys for private_key_jwt
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .reuseRefreshTokens(false)             // rotate refresh tokens
                        .build())
                .build();
    }

    private static RegisteredClient.Builder baseAuthCode(final String clientId, final String redirectUri,
                                                         final String... scopes) {
        final RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .scope(OidcScopes.OPENID);
        for (final String scope : scopes) {
            builder.scope(scope);
        }
        return builder;
    }
}
