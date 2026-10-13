/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.upgrade;

import io.helixiam.authorization.security.AuthorizationBlobs;
import io.helixiam.authorization.security.LegacyAuthorizationServerSerialization;
import io.helixiam.authorization.security.SessionBlobs;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.servlet.FlashMap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Spring Boot 4 upgrade: tokens and sign-in sessions written by HelixIAM 1.0 (Spring Boot 3.5.16, Spring Security
 * 6.5.11, Spring Authorization Server 1.5.8) are still readable after the upgrade. Both stores (queue/PostgreSQL and
 * Redis) persist these graphs with Java serialization; a blob that no longer deserializes would silently sign every
 * user out and invalidate every refresh token at the rolling upgrade. The blobs under {@code upgrade/boot3} were
 * written by {@link PersistedStateFixtures#main} on the 1.0 line.
 */
class PersistedStateUpgradeCompatibilityTest {

    @Test
    void anAuthorizationWrittenByTheBoot3Line_isReadWithEveryTokenAndAttribute() throws IOException {
        final OAuth2Authorization stored = AuthorizationBlobs.deserialize(blob("authorization.b64"));
        final OAuth2Authorization expected = PersistedStateFixtures.authorization();

        assertThat(stored).as("1.0 authorization blob is unreadable").isNotNull();
        assertThat(stored.getId()).isEqualTo(expected.getId());
        assertThat(stored.getRegisteredClientId()).isEqualTo(expected.getRegisteredClientId());
        assertThat(stored.getPrincipalName()).isEqualTo("ada");
        assertThat(stored.getAuthorizationGrantType()).isEqualTo(expected.getAuthorizationGrantType());
        assertThat(stored.getAuthorizedScopes()).containsExactlyElementsOf(expected.getAuthorizedScopes());
        assertThat((String) stored.getAttribute("state")).isEqualTo("state-xyz");

        final OAuth2AuthorizationRequest request = stored.getAttribute(OAuth2AuthorizationRequest.class.getName());
        assertThat(request.getClientId()).isEqualTo("web");
        assertThat(request.getRedirectUri()).isEqualTo("https://app.monthfold.com/cb");
        assertThat(request.getAdditionalParameters()).containsEntry("nonce", "n-1");
        assertThat(((Principal) stored.getAttribute(Principal.class.getName())).getName()).isEqualTo("ada");

        final OAuth2Authorization.Token<OAuth2AuthorizationCode> code = stored.getToken(OAuth2AuthorizationCode.class);
        assertThat(code.getToken().getTokenValue()).isEqualTo("code-1");
        assertThat(code.isInvalidated()).isTrue();

        final OAuth2Authorization.Token<OAuth2AccessToken> access = stored.getAccessToken();
        assertThat(access.getToken().getTokenValue()).isEqualTo("access-1");
        assertThat(access.getToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
        assertThat(access.getToken().getExpiresAt()).isEqualTo(PersistedStateFixtures.EXPIRES);
        assertThat(access.getClaims()).containsEntry("realm", "monthfold").containsEntry("sub", "ada");

        assertThat(stored.getRefreshToken().getToken().getTokenValue()).isEqualTo("refresh-1");
        assertThat(stored.getToken("refresh-1")).isNotNull();

        final OAuth2Authorization.Token<OidcIdToken> idToken = stored.getToken(OidcIdToken.class);
        assertThat(idToken.getToken().getClaims()).containsEntry("sid", "sid-1").containsEntry("acr", "urn:helix:acr:mfa");
    }

    @Test
    void aSignInSessionWrittenByTheBoot3Line_isKeptWithEveryAttribute() throws IOException {
        final Map<String, Object> attributes;
        try (LogCapture log = LogCapture.of(SessionBlobs.class)) {
            attributes = SessionBlobs.deserialize(blob("session.b64"));
            assertThat(log.text()).as("the store dropped the 1.0 session").doesNotContain("dropped");
        }

        assertThat(attributes).containsOnlyKeys(PersistedStateFixtures.sessionAttributes().keySet());
        final SecurityContext context = (SecurityContext) attributes.get("SPRING_SECURITY_CONTEXT");
        assertThat(context.getAuthentication()).isInstanceOf(MfaAuthentication.class);
        assertThat(context.getAuthentication().getName()).isEqualTo("ada");
        // MfaAuthentication itself is never "authenticated" (second factor pending); the first factor inside it is.
        assertThat(((MfaAuthentication) context.getAuthentication()).getOriginalUserObject().isAuthenticated()).isTrue();
        assertThat(((DefaultSavedRequest) attributes.get("SPRING_SECURITY_SAVED_REQUEST")).getRedirectUrl())
                .contains("/realms/monthfold/oauth2/authorize");
        assertThat(((CsrfToken) attributes.get(
                "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN")).getToken())
                .isEqualTo("csrf-1");
        final FlashMap flash = (FlashMap) ((List<?>) attributes.get(PersistedStateFixtures.FLASH_MAPS)).get(0);
        assertThat(flash.get("status")).isEqualTo("password-changed");
        assertThat(flash.getTargetRequestParams().getFirst("tab")).isEqualTo("password");
        assertThat(attributes).containsEntry("HELIX_SID", "sid-1").containsEntry("HELIX_AUTH_TIME", 1_790_000_000L);
    }

    @Test
    void theRedisTokenStore_readsAnAuthorizationWrittenByTheBoot3Line() throws IOException {
        // RedisOAuth2AuthorizationService stores the same Java serialization (JdkSerializationRedisSerializer).
        final byte[] bytes = Base64.getDecoder().decode(blob("authorization.b64"));
        final RedisSerializer<Object> serializer = LegacyAuthorizationServerSerialization.redisSerializer();

        final OAuth2Authorization stored = (OAuth2Authorization) serializer.deserialize(bytes);

        assertThat(stored.getRefreshToken().getToken().getTokenValue()).isEqualTo("refresh-1");
        assertThat(stored.getAccessToken().getClaims()).containsEntry("realm", "monthfold");
        // The writer is unchanged: byte-for-byte what JdkSerializationRedisSerializer writes.
        final OAuth2Authorization current = PersistedStateFixtures.authorization();
        assertThat(serializer.serialize(current)).isEqualTo(new JdkSerializationRedisSerializer().serialize(current));
    }

    @Test
    void withoutTheCompatibility_theBoot3AuthorizationIsUnreadable() throws IOException {
        // Why LegacyAuthorizationServerSerialization exists: Spring Security 7 changed the serialVersionUID.
        final byte[] bytes = Base64.getDecoder().decode(blob("authorization.b64"));
        try (ObjectInputStream plain = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            assertThatThrownBy(plain::readObject).isInstanceOf(InvalidClassException.class)
                    .hasMessageContaining("OAuth2Authorization");
        }
    }

    @Test
    void aClassWhoseSerializedFieldsChanged_isStillRejected() throws IOException {
        // OidcClientRegistration carried the same 1.x UID, but its fields changed: the compatibility does not apply.
        final byte[] bytes = Base64.getDecoder().decode(blob("changed-class.b64"));
        try (ObjectInputStream compatible = LegacyAuthorizationServerSerialization.objectInputStream(bytes)) {
            assertThatThrownBy(compatible::readObject).isInstanceOf(InvalidClassException.class)
                    .hasMessageContaining("OidcClientRegistration");
        }
        assertThatThrownBy(() -> LegacyAuthorizationServerSerialization.redisSerializer().deserialize(bytes))
                .isInstanceOf(SerializationException.class);
    }

    @Test
    void theAllowlistStillApplies_toAnUpgradedStream() throws IOException {
        // The session store's JEP-290 filter still rejects a gadget class, through the compatible stream.
        final Map<String, Object> gadget = new java.util.HashMap<>();
        gadget.put("x", new javax.management.BadAttributeValueExpException("payload"));
        try (LogCapture log = LogCapture.of(SessionBlobs.class)) {
            assertThat(SessionBlobs.deserialize(SessionBlobs.serialize(gadget))).isEmpty();
            assertThat(log.text()).contains("javax.management.BadAttributeValueExpException");
        }
    }

    @Test
    void aClientCredentialsAuthorizationWrittenBy10_isRead_withItsClientAuthentication() throws IOException {
        final OAuth2Authorization stored = AuthorizationBlobs.deserialize(blob("authorization-client-credentials.b64"));

        assertThat(stored).as("1.0 client_credentials blob is unreadable").isNotNull();
        assertThat(stored.getAuthorizationGrantType().getValue()).isEqualTo("client_credentials");
        assertThat(stored.getPrincipalName()).isEqualTo("ledger");
        assertThat(stored.getAccessToken().getToken().getTokenValue()).isEqualTo("access-cc");
        assertThat(stored.getAccessToken().getClaims()).containsEntry("sub", "ledger");
        final org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken client =
                stored.getAttribute(Principal.class.getName());
        assertThat(client.isAuthenticated()).isTrue();
        assertThat(client.getRegisteredClient().getClientId()).isEqualTo("ledger");
        assertThat(client.getRegisteredClient().getClientSettings().isRequireProofKey()).isFalse();
        assertThat(client.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive())
                .isEqualTo(java.time.Duration.ofMinutes(5));
        assertThat(client.getClientAuthenticationMethod().getValue()).isEqualTo("client_secret_basic");
    }

    @Test
    void aTokenExchangeAuthorizationWrittenBy10_isRead_withSubjectAndActClaim() throws IOException {
        final OAuth2Authorization stored = AuthorizationBlobs.deserialize(blob("authorization-token-exchange.b64"));

        assertThat(stored).as("1.0 token-exchange blob is unreadable").isNotNull();
        assertThat(stored.getAuthorizationGrantType().getValue())
                .isEqualTo("urn:ietf:params:oauth:grant-type:token-exchange");
        assertThat(((Principal) stored.getAttribute(Principal.class.getName())).getName()).isEqualTo("ada");
        assertThat(stored.getAccessToken().getToken().getTokenValue()).isEqualTo("access-tx");
        assertThat(stored.getAccessToken().getClaims()).containsEntry("sub", "ada")
                .containsEntry("act", java.util.Map.of("sub", "web"));
        assertThat(stored.getRegisteredClientId()).isEqualTo("client-tx");
    }

    @Test
    void aDeviceCodeAuthorizationWrittenBy10_isRead_readyForTheDevicesPoll() throws IOException {
        final OAuth2Authorization stored = AuthorizationBlobs.deserialize(blob("authorization-device-code.b64"));

        assertThat(stored).as("1.0 device-code blob is unreadable").isNotNull();
        assertThat(stored.getAuthorizationGrantType().getValue())
                .isEqualTo("urn:ietf:params:oauth:grant-type:device_code");
        assertThat(stored.getToken(org.springframework.security.oauth2.core.OAuth2DeviceCode.class).getToken()
                .getTokenValue()).isEqualTo("device-1");
        final OAuth2Authorization.Token<org.springframework.security.oauth2.core.OAuth2UserCode> userCode =
                stored.getToken(org.springframework.security.oauth2.core.OAuth2UserCode.class);
        assertThat(userCode.getToken().getTokenValue()).isEqualTo("WDJB-MJHT");
        assertThat(userCode.isInvalidated()).isTrue();
        assertThat(((Principal) stored.getAttribute(Principal.class.getName())).getName()).isEqualTo("ada");
        assertThat(stored.<java.util.Set<String>>getAttribute("scope")).containsExactly("openid");
        assertThat(stored.getAuthorizedScopes()).containsExactly("openid");
    }

    @Test
    void theCurrentLine_writesBlobsTheSameReaderAccepts() {
        // Guards the fixtures themselves: what this line writes, it reads.
        assertThat(AuthorizationBlobs.deserialize(AuthorizationBlobs.serialize(PersistedStateFixtures.authorization())))
                .isNotNull();
        assertThat(SessionBlobs.deserialize(SessionBlobs.serialize(PersistedStateFixtures.sessionAttributes())))
                .containsOnlyKeys(PersistedStateFixtures.sessionAttributes().keySet());
    }

    private static String blob(final String name) throws IOException {
        try (InputStream in = PersistedStateUpgradeCompatibilityTest.class.getResourceAsStream("/upgrade/boot3/" + name)) {
            assertThat(in).as(name).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
        }
    }
}
