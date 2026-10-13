/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import io.helixiam.authorization.security.AuthorizationBlobs;
import io.helixiam.upgrade.PersistedStateFixtures;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Spring Boot 4: Spring Security 7's {@code JwtGenerator} reads the previous ID token's {@code auth_time} as a
 * {@link Date} on a refresh. The store hands it out that way, for authorizations this line wrote and for those 1.0
 * wrote, without changing the stored claims metadata (introspection and the session roll-up read those).
 */
class RefreshAuthTimeTest {

    private static final Date AUTH_TIME = Date.from(Instant.ofEpochSecond(1_790_000_000L));

    @Test
    void anAuthorizationWrittenBy10_isHandedOutWithADateAuthTime() throws IOException {
        final OAuth2Authorization stored = AuthorizationBlobs.deserialize(blob());
        assertThat(stored.getToken(OidcIdToken.class).getToken().getClaims().get("auth_time")).isEqualTo(1_790_000_000L);
        final OAuth2AuthorizationService store = mock(OAuth2AuthorizationService.class);
        when(store.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(stored);
        when(store.findById("auth-1")).thenReturn(stored);
        final SsoSessionBindingAuthorizationService service = new SsoSessionBindingAuthorizationService(store);

        for (final OAuth2Authorization loaded : new OAuth2Authorization[] {
                service.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN), service.findById("auth-1")}) {
            final OAuth2Authorization.Token<OidcIdToken> idToken = loaded.getToken(OidcIdToken.class);
            final Date authTime = idToken.getToken().getClaim("auth_time"); // what JwtGenerator does
            assertThat(authTime).isEqualTo(AUTH_TIME);
            assertThat(idToken.getToken().getAuthenticatedAt()).isEqualTo(AUTH_TIME.toInstant());
            assertThat(idToken.getToken().getTokenValue()).isEqualTo("id-1");
            assertThat(idToken.getToken().getClaims()).containsEntry("sid", "sid-1").containsEntry("acr", "urn:helix:acr:mfa");
            assertThat(idToken.getMetadata()).isEqualTo(stored.getToken(OidcIdToken.class).getMetadata());
            assertThat(loaded.getRefreshToken().getToken().getTokenValue()).isEqualTo("refresh-1");
            assertThat(loaded.getAccessToken().getToken().getTokenValue()).isEqualTo("access-1");
            assertThat(loaded.getAttributes()).isEqualTo(stored.getAttributes());
        }
    }

    @Test
    void anAuthorizationWithoutANumericAuthTime_isHandedOutAsStored() {
        final OAuth2Authorization noAuthTime = OAuth2Authorization.from(PersistedStateFixtures.authorization())
                .token(new OidcIdToken("id-2", Instant.EPOCH, Instant.EPOCH.plusSeconds(1), java.util.Map.of("sub", "ada")))
                .build();

        assertThat(SsoSessionBindingAuthorizationService.withDateAuthTime(null)).isNull();
        assertThat(SsoSessionBindingAuthorizationService.withDateAuthTime(noAuthTime)).isSameAs(noAuthTime);
    }

    @Test
    void anAuthorizationSavedAgainAfterLoading_keepsTheDate_andLoadsUnchanged() throws IOException {
        // SAS saves what it loaded when it revokes or invalidates a token (the ID token stays): the stored ID token then
        // carries auth_time as a Date, while the token value and its claims metadata keep epoch seconds.
        final OAuth2Authorization loaded = SsoSessionBindingAuthorizationService.withDateAuthTime(
                AuthorizationBlobs.deserialize(blob()));
        final OAuth2Authorization revoked = OAuth2Authorization.from(loaded)
                .invalidate(loaded.getRefreshToken().getToken()).build();

        final OAuth2Authorization reloaded = AuthorizationBlobs.deserialize(AuthorizationBlobs.serialize(revoked));
        final OAuth2Authorization.Token<OidcIdToken> idToken = reloaded.getToken(OidcIdToken.class);
        assertThat(idToken.getToken().getClaims().get("auth_time")).isEqualTo(AUTH_TIME);
        assertThat(idToken.getClaims()).containsEntry("auth_time", 1_790_000_000L); // metadata: epoch seconds
        assertThat(idToken.getToken().getTokenValue()).isEqualTo("id-1");
        assertThat(SsoSessionBindingAuthorizationService.withDateAuthTime(reloaded)).isSameAs(reloaded);
    }

    private static String blob() throws IOException {
        try (InputStream in = RefreshAuthTimeTest.class.getResourceAsStream("/upgrade/boot3/authorization.b64")) {
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
        }
    }
}
