package io.helixiam.authorization.security.device;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Story 1 (CLI browser login): SAS refuses refresh tokens to public clients on the authorization_code grant.
 * This generator relaxes that ONLY for native-app clients (registered for the device grant, per RFC 8252) so a
 * CLI stays logged in via a rotating refresh token — while browser SPAs keep SAS's safe no-refresh behaviour.
 */
class NativeAppRefreshTokenGeneratorTest {

    private static final AuthorizationGrantType DEVICE_CODE =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code");

    private final NativeAppRefreshTokenGenerator generator = new NativeAppRefreshTokenGenerator();

    private static RegisteredClient.Builder client() {
        return RegisteredClient.withId("id").clientId("c")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .redirectUri("http://127.0.0.1/cb").scope("profile");
    }

    private static OAuth2TokenContext ctx(final RegisteredClient rc, final ClientAuthenticationMethod method,
                                          final OAuth2TokenType tokenType) {
        final OAuth2ClientAuthenticationToken clientAuth = new OAuth2ClientAuthenticationToken(rc, method, null);
        final org.springframework.security.core.Authentication grant =
                new org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken(
                        "code", clientAuth, null, null);
        return DefaultOAuth2TokenContext.builder()
                .registeredClient(rc)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(grant)
                .tokenType(tokenType)
                .build();
    }

    @Test
    void issuesRefreshToken_forNativeAppPublicClient() {
        final RegisteredClient nativeApp = client().authorizationGrantType(DEVICE_CODE).build();
        final Object tok = generator.generate(ctx(nativeApp, ClientAuthenticationMethod.NONE, OAuth2TokenType.REFRESH_TOKEN));
        assertNotNull(tok, "a native-app public client (device grant registered) gets a refresh token on auth-code");
        assertNotNull(((OAuth2RefreshToken) tok).getTokenValue());
    }

    @Test
    void withholdsRefreshToken_forNonNativePublicClient() {
        // No device_code grant ⇒ a browser SPA ⇒ keep SAS's guard (no refresh token).
        final RegisteredClient spa = client().build();
        assertNull(generator.generate(ctx(spa, ClientAuthenticationMethod.NONE, OAuth2TokenType.REFRESH_TOKEN)));
    }

    @Test
    void issuesRefreshToken_forConfidentialClient() {
        final RegisteredClient confidential = RegisteredClient.withId("id2").clientId("c2").clientSecret("{noop}s")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .redirectUri("https://app/cb").scope("profile").build();
        final Object tok = generator.generate(ctx(confidential, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, OAuth2TokenType.REFRESH_TOKEN));
        assertNotNull(tok, "confidential clients always get refresh tokens");
    }

    @Test
    void returnsNull_whenNotARefreshTokenRequest() {
        final RegisteredClient nativeApp = client().authorizationGrantType(DEVICE_CODE).build();
        assertNull(generator.generate(ctx(nativeApp, ClientAuthenticationMethod.NONE, OAuth2TokenType.ACCESS_TOKEN)));
    }
}
