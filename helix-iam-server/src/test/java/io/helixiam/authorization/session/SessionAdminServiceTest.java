package io.helixiam.authorization.session;

import io.helixiam.authorization.amqp.agent.AgentClientQuery;
import io.helixiam.authorization.amqp.agent.AgentIdentityDto;
import io.helixiam.authorization.amqp.agent.AgentIdentityPublisher;
import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P7: Sessions admin works in true SSO sessions — one row per browser login (rolled up across
 * the clients it touched, labelled with each client's human id), scoped to a realm, with cascading revoke.
 */
class SessionAdminServiceTest {

    private SessionStore store;
    private OAuth2AuthorizationService authorizationService;
    private ClientAdminPublisher clients;
    private SsoSessionStore ssoSessionStore;
    private SsoLogoutService ssoLogoutService;
    private UserAdminPublisher users;
    private AgentIdentityPublisher agents;
    private SessionAdminService service;

    @BeforeEach
    void setUp() {
        store = mock(SessionStore.class);
        authorizationService = mock(OAuth2AuthorizationService.class);
        clients = mock(ClientAdminPublisher.class);
        ssoSessionStore = mock(SsoSessionStore.class);
        ssoLogoutService = mock(SsoLogoutService.class);
        users = mock(UserAdminPublisher.class);
        agents = mock(AgentIdentityPublisher.class);
        service = new SessionAdminService(store, authorizationService, clients, ssoSessionStore,
                ssoLogoutService, users, agents, "https://idp.example");
    }

    private ClientDto client(final String id, final String clientId) {
        return client(id, clientId, null);
    }

    private ClientDto client(final String id, final String clientId, final String name) {
        return new ClientDto("gov", id, clientId, List.of(), List.of(), List.of(), null, null, null, name, null, List.of(), List.of(),
                false, false, true, null, null, null, null, false, null, null, null, false, null, null, null, null, null, null, null, null);
    }

    private static SsoSession sso(final String key, final String principal, final Instant at, final String... internalClientIds) {
        final List<SsoSession.ClientInSession> cs = java.util.Arrays.stream(internalClientIds)
                .map(rc -> new SsoSession.ClientInSession("authz-" + rc, rc, "authorization_code", List.of("openid"), at, at.plusSeconds(900)))
                .toList();
        return new SsoSession(key, principal, cs, at, at.plusSeconds(900));
    }

    @Test
    void listSso_rollsUpByRealm_labellingClientsWithTheirHumanId_newestFirst() {
        when(clients.list("gov")).thenReturn(List.of(client("rc-1", "gov-portal"), client("rc-2", "gov-cli")));
        final Instant t1 = Instant.parse("2026-06-26T10:00:00Z");
        final Instant t2 = Instant.parse("2026-06-26T11:00:00Z");
        when(ssoSessionStore.findAll()).thenReturn(List.of(
                sso("s-alice", "alice", t1, "rc-1", "rc-2"),
                sso("s-bob", "bob", t2, "rc-1"),
                sso("s-foreign", "x", t2, "rc-OTHER")));        // no client in this realm → excluded

        final List<SsoSessionView> views = service.listSso("gov");

        assertEquals(2, views.size());
        assertEquals("s-bob", views.get(0).ssoSessionId(), "newest first");
        assertEquals("s-alice", views.get(1).ssoSessionId());
        final SsoSessionView alice = views.get(1);
        assertEquals("gov", alice.realm());
        assertEquals(List.of("gov-portal", "gov-cli"),
                alice.clients().stream().map(SsoSessionView.ClientView::clientId).toList());
    }

    @Test
    void revokeSso_terminatesWithBackchannel_whenSessionBelongsToRealm() {
        when(clients.list("gov")).thenReturn(List.of(client("rc-1", "gov-portal")));
        when(ssoSessionStore.findById("s-alice")).thenReturn(sso("s-alice", "alice",
                Instant.parse("2026-06-26T10:00:00Z"), "rc-1"));

        assertTrue(service.revokeSso("gov", "s-alice"));
        verify(ssoLogoutService).terminate("s-alice", "gov", "https://idp.example/realms/gov");
    }

    @Test
    void revokeSso_refused_whenSessionBelongsToAnotherRealm() {
        when(clients.list("gov")).thenReturn(List.of(client("rc-1", "gov-portal")));
        when(ssoSessionStore.findById("s-foreign")).thenReturn(sso("s-foreign", "x",
                Instant.parse("2026-06-26T10:00:00Z"), "rc-OTHER"));

        assertFalse(service.revokeSso("gov", "s-foreign"));
        verify(ssoLogoutService, never()).terminate(any(), any(), any());
    }

    @Test
    void revokeSso_returnsFalse_whenSessionNotFound() {
        when(ssoSessionStore.findById("ghost")).thenReturn(null);
        assertFalse(service.revokeSso("gov", "ghost"));
        verify(ssoLogoutService, never()).terminate(any(), any(), any());
    }

    @Test
    void listIdentities_resolvesUsernameAndUserType_andFiltersByTypeAndQuery() {
        when(clients.list("gov")).thenReturn(List.of(client("rc-1", "gov-portal")));
        final Instant t = Instant.parse("2026-06-26T10:00:00Z");
        when(ssoSessionStore.findAll()).thenReturn(List.of(sso("sid-1", "u-uuid", t, "rc-1")));
        when(store.findAll()).thenReturn(List.of());
        when(agents.findByClient(new AgentClientQuery("gov", "gov-portal"))).thenReturn(null);
        when(users.get(new UserAdminRef("gov", "u-uuid"))).thenReturn(
                new UserAdminDto("gov", "u-uuid", "admin", "a@x", true, false, false, List.of(), Map.of(), null));

        final List<IdentitySessionView> all = service.listIdentities("gov", null, null);
        assertEquals(1, all.size());
        assertEquals(IdentityType.USER, all.get(0).identityType());
        assertEquals("admin", all.get(0).displayName(), "UUID resolved to username");
        assertEquals("SLO", all.get(0).revokeMode());

        assertTrue(service.listIdentities("gov", null, "agent").isEmpty(), "type filter excludes users");
        assertEquals(1, service.listIdentities("gov", "adm", null).size(), "q matches username");
        assertTrue(service.listIdentities("gov", "zzz", null).isEmpty(), "q misses");
    }

    @Test
    void listIdentities_includesServiceAccount_withClientName_andTokenRevoke() {
        when(clients.list("gov")).thenReturn(List.of(client("rc-2", "gov-cli", "CLI Backend")));
        when(ssoSessionStore.findAll()).thenReturn(List.of());
        final Instant t = Instant.parse("2026-06-26T11:00:00Z");
        when(store.findAll()).thenReturn(List.of(
                new SessionRow("b", "rc-2", "gov-cli", "client_credentials", List.of("api"), t, t.plusSeconds(300))));

        final List<IdentitySessionView> all = service.listIdentities("gov", null, null);
        assertEquals(1, all.size());
        assertEquals(IdentityType.SERVICE_ACCOUNT, all.get(0).identityType());
        assertEquals("CLI Backend", all.get(0).displayName());
        assertEquals("TOKEN", all.get(0).revokeMode());
        assertEquals(1, service.listIdentities("gov", null, "service_account").size());
    }

    @Test
    void listIdentities_marksAgent_whenClientBoundToAnAgent() {
        when(clients.list("gov")).thenReturn(List.of(client("rc-1", "agent-client")));
        final Instant t = Instant.parse("2026-06-26T10:00:00Z");
        when(ssoSessionStore.findAll()).thenReturn(List.of(sso("sid-a", "svc-sub", t, "rc-1")));
        when(store.findAll()).thenReturn(List.of());
        when(agents.findByClient(new AgentClientQuery("gov", "agent-client"))).thenReturn(
                new AgentIdentityDto("ag-1", "gov", "ci-bot", "CI Deploy Bot", "desc", "owner", "ACTIVE",
                        "client_credentials", "agent-client", "openid", true, null, null, null, "roles"));

        final List<IdentitySessionView> all = service.listIdentities("gov", null, null);
        assertEquals(IdentityType.AGENT, all.get(0).identityType());
        assertEquals("CI Deploy Bot", all.get(0).displayName());
    }

    @Test
    void listServiceAccounts_returnsOnlyClientCredentialRows_forTheRealm() {
        when(clients.list("gov")).thenReturn(List.of(client("rc-1", "gov-portal"), client("rc-2", "gov-cli")));
        final Instant t = Instant.parse("2026-06-26T11:00:00Z");
        when(store.findAll()).thenReturn(List.of(
                new SessionRow("a", "rc-1", "alice", "authorization_code", List.of("openid"), t, t.plusSeconds(900)),
                new SessionRow("b", "rc-2", "gov-cli", "client_credentials", List.of("api"), t, t.plusSeconds(300)),
                new SessionRow("c", "rc-OTHER", "x", "client_credentials", List.of(), t, t.plusSeconds(60))));

        final List<SessionSummary> svc = service.listServiceAccounts("gov");

        assertEquals(1, svc.size());
        assertEquals("gov-cli", svc.get(0).clientId());
    }
}
