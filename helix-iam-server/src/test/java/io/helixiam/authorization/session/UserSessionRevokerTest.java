/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.session.logout.BackchannelLogoutNotifier;
import io.helixiam.authorization.session.logout.LogoutTargetResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Open issue E7: which sessions and authorizations "revoke every session of a user" ends, and what it announces. */
class UserSessionRevokerTest {

    private static final String ISSUER = "https://id.example/realms/gov";

    private SsoSessionStore ssoSessions;
    private SessionStore rows;
    private OAuth2AuthorizationService authorizations;
    private SsoLogoutService ssoLogout;
    private SpringSessionStore browserSessions;
    private BackchannelLogoutNotifier backchannel;
    private LogoutTargetResolver targets;
    private UserSessionRevoker revoker;

    @BeforeEach
    void setUp() {
        ssoSessions = mock(SsoSessionStore.class);
        rows = mock(SessionStore.class);
        authorizations = mock(OAuth2AuthorizationService.class);
        ssoLogout = mock(SsoLogoutService.class);
        browserSessions = mock(SpringSessionStore.class);
        backchannel = mock(BackchannelLogoutNotifier.class);
        targets = mock(LogoutTargetResolver.class);
        final ClientAdminPublisher clients = mock(ClientAdminPublisher.class);
        when(clients.list("gov")).thenReturn(List.of(client("rc-web"), client("rc-portal")));
        revoker = new UserSessionRevoker(ssoSessions, rows, authorizations, ssoLogout, browserSessions, backchannel,
                targets, clients, "https://id.example");
    }

    private static ClientDto client(final String id) {
        return new ClientDto("gov", id, id, List.of(), List.of(), List.of(), null, null, null, id, null, List.of(),
                List.of(), false, false, true, null, null, null, null, false, null, null, null, false, null, null, null,
                null, null, null, null, null);
    }

    private static SsoSession session(final String sid, final String principal, final String clientId,
                                      final String authorizationId) {
        return new SsoSession(sid, principal, List.of(new SsoSession.ClientInSession(authorizationId, clientId,
                "authorization_code", List.of("openid"), Instant.now(), Instant.now().plusSeconds(600))),
                Instant.now(), Instant.now().plusSeconds(600));
    }

    private static SessionRow row(final String id, final String clientId, final String principal) {
        return new SessionRow(id, clientId, principal, "authorization_code", List.of("openid"), Instant.now(),
                Instant.now().plusSeconds(600));
    }

    @Test
    void endsTheUsersSsoSessionsOfTheRealm_thenOrphanAuthorizations_announcedBySubOnly() {
        final SsoSession mine = session("sid-1", "u1", "rc-web", "a1");
        when(ssoSessions.findAll()).thenReturn(List.of(mine,
                session("sid-2", "u2", "rc-web", "a2"),          // another user
                session("sid-3", "u1", "rc-elsewhere", "a3")));   // the same principal at another realm's client
        when(ssoLogout.terminate("sid-1", "gov", ISSUER)).thenReturn(mine);
        when(rows.findAll()).thenReturn(List.of(row("a4", "rc-portal", "u1"), row("a5", "rc-portal", "u2"),
                row("a6", "rc-elsewhere", "u1")));
        final OAuth2Authorization a4 = mock(OAuth2Authorization.class);
        when(authorizations.findById("a4")).thenReturn(a4);
        final List<BackchannelLogoutNotifier.Target> portal =
                List.of(new BackchannelLogoutNotifier.Target("rc-portal", "https://portal.example/bcl"));
        when(targets.backchannelTargets("gov", List.of("rc-portal"))).thenReturn(portal);
        when(browserSessions.deleteByPrincipal("u1")).thenReturn(2);

        final UserSessionRevoker.Result result = revoker.revokeAll("gov", "u1");

        assertThat(result).isEqualTo(new UserSessionRevoker.Result(1, 2, 2));
        verify(ssoLogout).terminate("sid-1", "gov", ISSUER);
        verify(ssoLogout, never()).terminate(eq("sid-2"), any(), any());
        verify(ssoLogout, never()).terminate(eq("sid-3"), any(), any());
        verify(authorizations).remove(a4);
        verify(authorizations, never()).findById("a5");
        verify(authorizations, never()).findById("a6");
        verify(backchannel).notifyClients(eq("gov"), eq(ISSUER), eq("u1"), isNull(), eq(portal));
        verify(browserSessions).deleteByPrincipal("u1");
    }

    @Test
    void nothingToEnd_announcesNothing() {
        when(ssoSessions.findAll()).thenReturn(List.of());
        when(rows.findAll()).thenReturn(List.of());

        assertThat(revoker.revokeAll("gov", "u1")).isEqualTo(new UserSessionRevoker.Result(0, 0, 0));
        verify(backchannel, never()).notifyClients(any(), any(), any(), any(), any());
    }
}
