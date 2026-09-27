/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.session.SessionRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** rc.6 item 7b: signing out one browser from the account console touches only the caller's other sessions. */
class AccountSessionServiceSignOutTest {

    private static final String REALM = "monthfold";
    private static final String ISSUER = "https://auth.example/realms/monthfold";

    private final SsoSessionStore ssoSessions = mock(SsoSessionStore.class);
    private final SsoLogoutService logout = mock(SsoLogoutService.class);
    private final BrowserSessionRegistry registry = mock(BrowserSessionRegistry.class);
    private final HttpSessionTerminator httpSessions = mock(HttpSessionTerminator.class);
    @SuppressWarnings("unchecked")
    private final ObjectProvider<SessionRepository<?>> repository = mock(ObjectProvider.class);
    private final AccountSessionService service = new AccountSessionService(mock(SessionAdminService.class), ssoSessions,
            logout, registry, repository, httpSessions, mock(SessionRevocation.class), "https://auth.example");

    @Test
    void anotherBrowserOfTheUser_isSignedOut_appsAndBrowserSession() {
        when(registry.find("joe", "sid-phone")).thenReturn(Optional.of(new BrowserSessionRegistry.Entry("sid-phone", "joe",
                "http-1", DeviceLabel.UNKNOWN, Instant.EPOCH)));
        when(ssoSessions.findById("sid-phone")).thenReturn(new SsoSession("sid-phone", "joe", List.of(), Instant.EPOCH,
                null));

        assertThat(service.signOutBrowser(REALM, "joe", "sid-phone", "sid-here")).isTrue();

        verify(logout).terminate("sid-phone", REALM, ISSUER);
        verify(httpSessions).deleteAll(List.of("http-1"));
        verify(registry).remove("joe", "sid-phone");
    }

    @Test
    void thisBrowser_isRefused() {
        assertThat(service.signOutBrowser(REALM, "joe", "sid-here", "sid-here")).isFalse();
        verify(logout, never()).terminate(anyString(), anyString(), anyString());
        verify(httpSessions, never()).deleteAll(any());
    }

    @Test
    void someoneElsesSession_isRefused() {
        when(registry.find("joe", "sid-bob")).thenReturn(Optional.empty());
        when(ssoSessions.findById("sid-bob")).thenReturn(new SsoSession("sid-bob", "bob", List.of(), Instant.EPOCH, null));

        assertThat(service.signOutBrowser(REALM, "joe", "sid-bob", "sid-here")).isFalse();

        verify(logout, never()).terminate(anyString(), anyString(), anyString());
        verify(httpSessions, never()).deleteAll(any());
        verify(registry, never()).remove(anyString(), anyString());
    }

    @Test
    void noSid_isRefused() {
        assertThat(service.signOutBrowser(REALM, "joe", " ", "sid-here")).isFalse();
        assertThat(service.signOutBrowser(REALM, "joe", null, "sid-here")).isFalse();
    }
}
