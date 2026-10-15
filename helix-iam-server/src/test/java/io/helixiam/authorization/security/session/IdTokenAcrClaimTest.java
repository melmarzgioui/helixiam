/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 3: the brokered level of assurance reaches the ID token {@code acr}, the same way
 * {@link IdTokenSessionClaims} already emits {@code sid}/{@code auth_time} — copied from
 * {@link SsoSessionBindingAuthorizationService#ACR_ATTRIBUTE} on the authorization, id_token only, kept on
 * refresh (the attribute travels with the authorization), absent when no brokered login bound one.
 */
class IdTokenAcrClaimTest {

    @Test
    void authorizationCarryingAcr_emitsItOnTheIdToken() {
        final JwtEncodingContext context = idTokenContext(authorization("http://eidas.europa.eu/LoA/high"));

        IdTokenSessionClaims.apply(context);

        assertThat(context.getClaims().build().<String>getClaim(IdTokenSessionClaims.ACR))
                .isEqualTo("http://eidas.europa.eu/LoA/high");
    }

    @Test
    void absentAcrAttribute_emitsNoAcrClaim() {
        final JwtEncodingContext context = idTokenContext(authorization(null));

        IdTokenSessionClaims.apply(context);

        assertThat(context.getClaims().build().<String>getClaim(IdTokenSessionClaims.ACR)).isNull();
    }

    @Test
    void anAccessToken_isNeverGivenAnAcrClaim() {
        final JwtEncodingContext context = JwtEncodingContext.with(JwsHeader.with(() -> "RS256"),
                        JwtClaimsSet.builder().subject("user-1").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)))
                .registeredClient(client())
                .authorization(authorization("http://eidas.europa.eu/LoA/high"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        IdTokenSessionClaims.apply(context);

        assertThat(context.getClaims().build().<String>getClaim(IdTokenSessionClaims.ACR)).isNull();
    }

    private static JwtEncodingContext idTokenContext(final OAuth2Authorization authorization) {
        return JwtEncodingContext.with(JwsHeader.with(() -> "RS256"),
                        JwtClaimsSet.builder().subject("user-1").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)))
                .registeredClient(client())
                .authorization(authorization)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .tokenType(new OAuth2TokenType("id_token"))
                .build();
    }

    private static OAuth2Authorization authorization(final String acr) {
        final Instant now = Instant.now();
        final OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client())
                .principalName("user-1")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new OAuth2AuthorizationCode("code", now, now.plusSeconds(60)));
        if (acr != null) {
            builder.attribute(SsoSessionBindingAuthorizationService.ACR_ATTRIBUTE, acr);
        }
        return builder.build();
    }

    private static RegisteredClient client() {
        return RegisteredClient.withId("c1").clientId("web")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://app.example/cb").build();
    }

    // ------------------------------------------------------------------ verify-only: verified_claims

    @Test
    void boundVerifiedClaims_reachTheIdTokenAsFreshMutableMaps() {
        final OAuth2Authorization authorization = OAuth2Authorization.from(authorization("http://eidas.europa.eu/LoA/high"))
                .attribute(SsoSessionBindingAuthorizationService.VERIFIED_CLAIMS_ATTRIBUTE,
                        "{\"verification\":{\"trust_framework\":\"eidas\"},\"claims\":{\"age_over_18\":true,"
                                + "\"nationalities\":\"NL\"}}")
                .build();
        final JwtEncodingContext context = idTokenContext(authorization);

        IdTokenSessionClaims.apply(context);

        final Object claim = context.getClaims().build().getClaim(IdTokenSessionClaims.VERIFIED_CLAIMS);
        assertThat(claim).isInstanceOf(java.util.LinkedHashMap.class);
        @SuppressWarnings("unchecked")
        final java.util.Map<String, Object> verified = (java.util.Map<String, Object>) claim;
        assertThat(verified.get("claims")).isInstanceOf(java.util.LinkedHashMap.class)
                .isEqualTo(java.util.Map.of("age_over_18", true, "nationalities", "NL"));
        assertThat(verified.get("verification")).isEqualTo(java.util.Map.of("trust_framework", "eidas"));
    }

    @Test
    void unreadableOrAbsentVerifiedClaims_emitNothing() {
        final JwtEncodingContext broken = idTokenContext(OAuth2Authorization.from(authorization(null))
                .attribute(SsoSessionBindingAuthorizationService.VERIFIED_CLAIMS_ATTRIBUTE, "[not json").build());
        IdTokenSessionClaims.apply(broken);
        assertThat(broken.getClaims().build().<Object>getClaim(IdTokenSessionClaims.VERIFIED_CLAIMS)).isNull();

        final JwtEncodingContext none = idTokenContext(authorization(null));
        IdTokenSessionClaims.apply(none);
        assertThat(none.getClaims().build().<Object>getClaim(IdTokenSessionClaims.VERIFIED_CLAIMS)).isNull();
    }

    @Test
    void aRefreshGrantIdToken_neverCarriesVerifiedClaims() {
        final OAuth2Authorization authorization = OAuth2Authorization.from(authorization(null))
                .attribute(SsoSessionBindingAuthorizationService.VERIFIED_CLAIMS_ATTRIBUTE, "{\"claims\":{}}").build();
        final JwtEncodingContext refresh = JwtEncodingContext.with(JwsHeader.with(() -> "RS256"),
                        JwtClaimsSet.builder().subject("user-1").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)))
                .registeredClient(client()).authorization(authorization)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenType(new OAuth2TokenType("id_token")).build();

        IdTokenSessionClaims.apply(refresh);

        assertThat(refresh.getClaims().build().<Object>getClaim(IdTokenSessionClaims.VERIFIED_CLAIMS)).isNull();
    }
}
