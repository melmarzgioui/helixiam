package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.authzstore.AuthorizationRecord;
import group.mfnr.authorization.amqp.authzstore.AuthorizationStorePublisher;
import group.mfnr.authorization.security.AuthorizationBlobs;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (Q2): the queue-backed SSO + session readers pull authorizations from the subscriber over AMQP,
 * deserialize the blobs, and produce the same rollup the JDBC/Redis readers do — sharing
 * {@link SsoSessionRollup}. Two clients under one {@code sid} collapse to one SSO session; client_credentials
 * is excluded.
 */
class QueueSessionStoresTest {

    /** Fake store whose listAll returns the supplied serialized authorizations. */
    private static AuthorizationStorePublisher storeOf(final OAuth2Authorization... auths) {
        final List<AuthorizationRecord> records = java.util.Arrays.stream(auths)
                .map(a -> new AuthorizationRecord(a.getId(), a.getPrincipalName(),
                        a.getAuthorizationGrantType().getValue(), AuthorizationBlobs.serialize(a), List.of(), null))
                .toList();
        return new AuthorizationStorePublisher() {
            @Override public Boolean save(final AuthorizationRecord r) { return true; }
            @Override public Boolean remove(final RemoveRequest r) { return true; }
            @Override public AuthorizationRecord findById(final String id) { return null; }
            @Override public AuthorizationRecord findByToken(final String t) { return null; }
            @Override public List<AuthorizationRecord> listAll(final String marker) { return records; }
        };
    }

    private static OAuth2Authorization authWithSid(final String id, final String client, final String sid) {
        final RegisteredClient rc = RegisteredClient.withId(client).clientId(client)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://a/cb").build();
        final Instant now = Instant.now();
        return OAuth2Authorization.withRegisteredClient(rc).id(id).principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(java.util.Set.of("openid"))
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "at-" + id, now, now.plusSeconds(300)))
                .token(new OidcIdToken("idt-" + id, now, now.plusSeconds(300), Map.of("sub", "alice", "sid", sid)))
                .build();
    }

    private static OAuth2Authorization serviceAccount(final String id) {
        final RegisteredClient rc = RegisteredClient.withId(id).clientId(id)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
        final Instant now = Instant.now();
        return OAuth2Authorization.withRegisteredClient(rc).id(id).principalName(id)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "at-" + id, now, now.plusSeconds(300)))
                .build();
    }

    @Test
    void ssoStore_rollsUpTwoClientsUnderOneSid_andExcludesServiceAccounts() {
        final AuthorizationStorePublisher store = storeOf(
                authWithSid("a1", "client-1", "SID-X"),
                authWithSid("a2", "client-2", "SID-X"),
                serviceAccount("svc-1"));
        final QueueSsoSessionStore sso = new QueueSsoSessionStore(store);

        final List<SsoSession> sessions = sso.findAll();

        assertThat(sessions).hasSize(1);
        assertThat(sessions.get(0).ssoSessionId()).isEqualTo("SID-X");
        assertThat(sessions.get(0).principalName()).isEqualTo("alice");
        assertThat(sessions.get(0).authorizationIds()).containsExactlyInAnyOrder("a1", "a2");
        assertThat(sso.findById("SID-X")).isNotNull();
        assertThat(sso.findById("nope")).isNull();
    }

    @Test
    void sessionStore_mapsEachAuthorizationToARow() {
        final AuthorizationStorePublisher store = storeOf(
                authWithSid("a1", "client-1", "SID-X"), serviceAccount("svc-1"));
        final QueueSessionStore sessions = new QueueSessionStore(store);

        final List<SessionRow> rows = sessions.findAll();

        assertThat(rows).hasSize(2); // session store lists ALL authorizations incl. service accounts
        assertThat(rows).anySatisfy(r -> {
            assertThat(r.id()).isEqualTo("a1");
            assertThat(r.principalName()).isEqualTo("alice");
            assertThat(r.grantType()).isEqualTo("authorization_code");
            assertThat(r.scopes()).contains("openid");
            assertThat(r.issuedAt()).isNotNull();
            assertThat(r.expiresAt()).isNotNull();
        });
    }
}
