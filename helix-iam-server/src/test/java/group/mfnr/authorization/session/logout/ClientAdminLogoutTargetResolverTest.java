package group.mfnr.authorization.session.logout;

import group.mfnr.authorization.amqp.client.ClientAdminPublisher;
import group.mfnr.authorization.amqp.client.ClientDto;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P6: resolves the realm's clients down to those that (a) took part in the session AND
 * (b) registered a back-/front-channel logout URI.
 */
class ClientAdminLogoutTargetResolverTest {

    private final ClientAdminPublisher publisher = mock(ClientAdminPublisher.class);
    private final ClientAdminLogoutTargetResolver resolver = new ClientAdminLogoutTargetResolver(publisher);

    /** id = internal registered-client id (how a session references it); clientId = the OAuth client_id. */
    private static ClientDto client(final String id, final String clientId, final String backchannel, final String frontchannel) {
        return new ClientDto("master", id, clientId, List.of(), List.of(), List.of(), null, null, null, null, null,
                List.of(), List.of(), false, false, true, null, null, null, null, false, null, null, null, false,
                null, null, backchannel, frontchannel, null, null, null, null);
    }

    @Test
    void backchannelTargets_resolvedByInternalId_emittingTheOAuthClientId() {
        when(publisher.list("master")).thenReturn(List.of(
                client("id-a", "spa-app", "https://a/logout", null),
                client("id-b", "b", null, null),                  // in session, no back-channel URI
                client("id-c", "c", "https://c/logout", null),    // has a URI but NOT in session
                client("id-d", "d", "  ", null)));                // blank URI ignored

        // A session references clients by their internal registered_client_id.
        final List<BackchannelLogoutNotifier.Target> targets =
                resolver.backchannelTargets("master", List.of("id-a", "id-b", "id-d"));

        assertEquals(1, targets.size());
        assertEquals("spa-app", targets.get(0).clientId(), "aud must be the OAuth client_id, not our internal id");
        assertEquals("https://a/logout", targets.get(0).backchannelLogoutUri());
    }

    @Test
    void backchannelTargets_alsoMatchByOAuthClientId() {
        when(publisher.list("master")).thenReturn(List.of(client("id-a", "spa-app", "https://a/logout", null)));
        assertEquals(1, resolver.backchannelTargets("master", List.of("spa-app")).size());
    }

    @Test
    void frontchannelTargets_onlyForSessionClientsWithAUri() {
        when(publisher.list("master")).thenReturn(List.of(
                client("id-a", "a", null, "https://a/fc"),
                client("id-b", "b", null, null)));

        final List<LogoutTargetResolver.FrontchannelTarget> targets =
                resolver.frontchannelTargets("master", List.of("id-a", "id-b"));

        assertEquals(1, targets.size());
        assertEquals("https://a/fc", targets.get(0).frontchannelLogoutUri());
    }

    @Test
    void noClients_yieldsNoTargets() {
        when(publisher.list("master")).thenReturn(null);
        assertTrue(resolver.backchannelTargets("master", List.of("a")).isEmpty());
    }
}
