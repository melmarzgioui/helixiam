/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.session.logout.BackchannelLogoutNotifier;
import io.helixiam.authorization.session.logout.LogoutTargetResolver;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P5: terminating an SSO session removes every client authorization it spans (so no token
 * can be refreshed) AND deletes the user's HTTP session(s) — one logout ends the session everywhere.
 */
class SsoLogoutServiceTest {

    private final SsoSessionStore sessionStore = mock(SsoSessionStore.class);
    private final OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
    private final SpringSessionStore springSessionStore = mock(SpringSessionStore.class);
    private final BackchannelLogoutNotifier notifier = mock(BackchannelLogoutNotifier.class);
    private final LogoutTargetResolver targetResolver = mock(LogoutTargetResolver.class);
    private final HttpSessionTerminator httpSessions = mock(HttpSessionTerminator.class);
    private final SsoLogoutService service = new SsoLogoutService(sessionStore, authorizationService,
            springSessionStore, notifier, targetResolver, httpSessions);

    private static SsoSession session(final String key, final String principal, final String... authzIds) {
        final List<SsoSession.ClientInSession> clients = java.util.Arrays.stream(authzIds)
                .map(id -> new SsoSession.ClientInSession(id, "client-" + id, "authorization_code", List.of("openid"),
                        Instant.EPOCH, Instant.EPOCH))
                .toList();
        return new SsoSession(key, principal, clients, Instant.EPOCH, Instant.EPOCH);
    }

    @Test
    void terminate_removesEveryAuthorization_andDeletesTheHttpSession() {
        final SsoSession sso = session("alice", "alice", "a1", "a2", "a3");
        when(sessionStore.findById("alice")).thenReturn(sso);
        when(authorizationService.findById("a1")).thenReturn(mock(OAuth2Authorization.class));
        when(authorizationService.findById("a2")).thenReturn(mock(OAuth2Authorization.class));
        when(authorizationService.findById("a3")).thenReturn(mock(OAuth2Authorization.class));

        final SsoSession terminated = service.terminate("alice");

        assertEquals("alice", terminated.ssoSessionId());
        verify(authorizationService, org.mockito.Mockito.times(3)).remove(any());
        verify(springSessionStore).deleteByPrincipal("alice");
    }

    @Test
    void terminate_sidBoundSession_endsOnlyItsOwnBrowserSessions_notEveryOneOfTheUser() {
        final SsoSession sso = session("sid-1", "alice", "a1", "a2", "a3");
        when(sessionStore.findById("sid-1")).thenReturn(sso);
        final OAuth2Authorization a1 = bound("sid-1", "http-1");
        final OAuth2Authorization a2 = bound("sid-1", "http-2");
        final OAuth2Authorization a3 = bound("sid-1", "http-1");
        when(authorizationService.findById("a1")).thenReturn(a1);
        when(authorizationService.findById("a2")).thenReturn(a2);
        when(authorizationService.findById("a3")).thenReturn(a3);

        service.terminate("sid-1");

        verify(authorizationService, org.mockito.Mockito.times(3)).remove(any());
        verify(httpSessions).deleteAll(new java.util.LinkedHashSet<>(List.of("http-1", "http-2")));
        verify(springSessionStore, never()).deleteByPrincipal(any());
    }

    private static OAuth2Authorization bound(final String sid, final String httpSession) {
        final OAuth2Authorization a = mock(OAuth2Authorization.class);
        when(a.getAttribute(io.helixiam.authorization.security.session.SsoSessionBindingAuthorizationService.SID_ATTRIBUTE))
                .thenReturn(sid);
        when(a.getAttribute(io.helixiam.authorization.security.session.SsoSessionBindingAuthorizationService.HTTP_SESSION_ATTRIBUTE))
                .thenReturn(httpSession);
        return a;
    }

    @Test
    void terminate_withRealmAndIssuer_fansOutBackchannelLogoutTokens() {
        final SsoSession sso = session("alice", "alice", "a1", "a2");
        when(sessionStore.findById("alice")).thenReturn(sso);
        when(authorizationService.findById(any())).thenReturn(mock(OAuth2Authorization.class));
        final List<BackchannelLogoutNotifier.Target> targets = List.of(
                new BackchannelLogoutNotifier.Target("client-a1", "https://a/logout"));
        when(targetResolver.backchannelTargets(eq("master"), any())).thenReturn(targets);

        service.terminate("alice", "master", "https://idp/realms/master");

        verify(authorizationService, org.mockito.Mockito.times(2)).remove(any());
        verify(notifier).notifyClients("master", "https://idp/realms/master", "alice", "alice", targets);
    }

    @Test
    void terminate_withoutRealm_doesNotFanOut() {
        final SsoSession sso = session("alice", "alice", "a1");
        when(sessionStore.findById("alice")).thenReturn(sso);
        when(authorizationService.findById(any())).thenReturn(mock(OAuth2Authorization.class));

        service.terminate("alice");

        verify(notifier, never()).notifyClients(any(), any(), any(), any(), any());
    }

    @Test
    void terminate_unknownSession_isANoOp() {
        when(sessionStore.findById("ghost")).thenReturn(null);

        org.junit.jupiter.api.Assertions.assertNull(service.terminate("ghost"));

        verify(authorizationService, never()).remove(any());
        verify(springSessionStore, never()).deleteByPrincipal(any());
    }
}
