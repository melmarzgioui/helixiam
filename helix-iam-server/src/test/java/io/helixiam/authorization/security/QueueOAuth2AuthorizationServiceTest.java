package io.helixiam.authorization.security;

import io.helixiam.authorization.amqp.authzstore.AuthorizationRecord;
import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (Q1): the queue-backed {@link org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService}
 * delegates persistence to the subscriber over AMQP (an opaque blob + token-value index), mirroring the Redis
 * tier. Verified against an in-memory fake store: save → findByToken/findById round-trips the authorization,
 * remove deletes it.
 */
class QueueOAuth2AuthorizationServiceTest {

    /** In-memory stand-in for the subscriber-backed store. */
    private static final class FakeStore implements AuthorizationStorePublisher {
        final Map<String, AuthorizationRecord> byId = new HashMap<>();
        final Map<String, String> tokenIndex = new HashMap<>();

        @Override public Boolean save(final AuthorizationRecord r) {
            byId.put(r.id(), r);
            r.tokenKeys().forEach(k -> tokenIndex.put(k, r.id()));
            return true;
        }
        @Override public Boolean remove(final RemoveRequest req) {
            byId.remove(req.id());
            req.tokenKeys().forEach(tokenIndex::remove);
            return true;
        }
        @Override public AuthorizationRecord findById(final String id) {
            return byId.get(id);
        }
        @Override public AuthorizationRecord findByToken(final String tokenKey) {
            final String id = tokenIndex.get(tokenKey);
            return id == null ? null : byId.get(id);
        }
        @Override public java.util.List<AuthorizationRecord> listAll(final String marker) {
            return new java.util.ArrayList<>(byId.values());
        }
    }

    private static OAuth2Authorization sampleAuthorization() {
        final RegisteredClient client = RegisteredClient.withId("client-1").clientId("c")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://app.example/cb").build();
        return OAuth2Authorization.withRegisteredClient(client)
                .id("auth-1").principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2ParameterNames.STATE, "state-xyz")
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "tok-abc",
                        Instant.now(), Instant.now().plusSeconds(300)))
                .build();
    }

    @Test
    void save_thenFindByToken_roundTripsTheAuthorization() {
        final FakeStore store = new FakeStore();
        final QueueOAuth2AuthorizationService service = new QueueOAuth2AuthorizationService(store);

        service.save(sampleAuthorization());

        final OAuth2Authorization byToken = service.findByToken("tok-abc", OAuth2TokenType.ACCESS_TOKEN);
        assertThat(byToken).isNotNull();
        assertThat(byToken.getId()).isEqualTo("auth-1");
        assertThat(byToken.getPrincipalName()).isEqualTo("alice");
        assertThat(byToken.getAccessToken().getToken().getTokenValue()).isEqualTo("tok-abc");
        // state is also indexed
        assertThat(service.findByToken("state-xyz", null)).isNotNull();
        assertThat(service.findById("auth-1")).isNotNull();
    }

    @Test
    void save_indexesDeviceCodeAndUserCode_soDeviceFlowPollResolves() {
        // Story 4 (CLI device grant): at the device_authorization step the authorization contains ONLY a
        // device_code + user_code (no access/refresh/authz-code yet). Both must be indexed so the CLI's token
        // poll (findByToken by device_code) and the /activate page (findByToken by user_code) resolve.
        final FakeStore store = new FakeStore();
        final QueueOAuth2AuthorizationService service = new QueueOAuth2AuthorizationService(store);

        final RegisteredClient client = RegisteredClient.withId("cli").clientId("kubedna-cli")
                .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code"))
                .build();
        final OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(client)
                .id("dev-auth").principalName("alice")
                .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code"))
                .token(new org.springframework.security.oauth2.core.OAuth2DeviceCode(
                        "dev-code-123", Instant.now(), Instant.now().plusSeconds(300)))
                .token(new org.springframework.security.oauth2.core.OAuth2UserCode(
                        "WDJB-MJHT", Instant.now(), Instant.now().plusSeconds(300)))
                .build();

        service.save(auth);

        assertThat(service.findByToken("dev-code-123", null)).as("device_code resolves").isNotNull();
        assertThat(service.findByToken("WDJB-MJHT", null)).as("user_code resolves").isNotNull();
    }

    @Test
    void deserialize_rejectsTypeOutsideTheAllowlist() throws Exception {
        // A blob of a Serializable type NOT in the deserialization allowlist (here java.io.File, a stand-in for
        // any gadget class) must be safely rejected, never instantiated — it surfaces as absent (null).
        final java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        try (java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos)) {
            oos.writeObject(new java.io.File("/etc/passwd"));
        }
        final String evilBlob = java.util.Base64.getEncoder().encodeToString(bos.toByteArray());
        final FakeStore store = new FakeStore();
        store.byId.put("evil", new AuthorizationRecord("evil", "p", "authorization_code",
                evilBlob, java.util.List.of(), null));
        final QueueOAuth2AuthorizationService service = new QueueOAuth2AuthorizationService(store);

        assertThat(service.findById("evil")).isNull();
    }

    @Test
    void remove_deletesIdAndTokenIndex() {
        final FakeStore store = new FakeStore();
        final QueueOAuth2AuthorizationService service = new QueueOAuth2AuthorizationService(store);
        final OAuth2Authorization auth = sampleAuthorization();
        service.save(auth);

        service.remove(auth);

        assertThat(service.findById("auth-1")).isNull();
        assertThat(service.findByToken("tok-abc", OAuth2TokenType.ACCESS_TOKEN)).isNull();
        assertThat(store.byId).isEmpty();
        assertThat(store.tokenIndex).isEmpty();
    }
}
