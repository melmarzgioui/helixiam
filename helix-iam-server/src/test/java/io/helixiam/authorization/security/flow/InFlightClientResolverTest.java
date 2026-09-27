/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.savedrequest.SavedRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (named flows): resolving the in-flight relying party's {@code client_id} from the OAuth
 * authorize request Spring Security cached before bouncing the user to login — so the login flow can be
 * chosen per client.
 */
class InFlightClientResolverTest {

    @Test
    void clientIdOf_returnsNull_whenThereIsNoSavedRequest() {
        assertNull(InFlightClientResolver.clientIdOf(null));
    }

    @Test
    void clientIdOf_returnsNull_whenTheSavedRequestCarriesNoClientId() {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getParameterValues("client_id")).thenReturn(null);
        assertNull(InFlightClientResolver.clientIdOf(saved));
    }

    @Test
    void clientIdOf_extractsTheClientId_fromTheCachedAuthorizeRequest() {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getParameterValues("client_id")).thenReturn(new String[]{"gov-portal"});
        assertEquals("gov-portal", InFlightClientResolver.clientIdOf(saved));
    }

    @Test
    void pendingAuthorizeUrl_isTheSavedAuthorizeRequestAsAPathOnThisServer_neverAnAbsoluteUrl() {
        // CodeQL #255 (java/unvalidated-url-redirection): the target is built from the saved request's path and query
        // only, so whatever host that request carried, the redirect stays on this server.
        assertEquals(java.util.Optional.of("/realms/acme/oauth2/authorize?client_id=web&state=a%20b"),
                InFlightClientResolver.pendingAuthorizeUrl(withSaved("https://evil.example:8443/realms/acme/oauth2/authorize?client_id=web&state=a%20b", "GET")));
        assertEquals(java.util.Optional.of("/oauth2/authorize"),
                InFlightClientResolver.pendingAuthorizeUrl(withSaved("http://idp.example/oauth2/authorize", "GET")));
    }

    @Test
    void pendingAuthorizeUrl_isEmpty_forAnythingButAPlainGetOfTheAuthorizeEndpoint() {
        for (final String url : new String[]{"https://idp.example/realms/acme/login", "https://idp.example//evil.example/oauth2/authorize",
                "https://idp.example/x\\y/oauth2/authorize", "not a uri/oauth2/authorize"}) {
            assertEquals(java.util.Optional.empty(), InFlightClientResolver.pendingAuthorizeUrl(withSaved(url, "GET")), url);
        }
        assertEquals(java.util.Optional.empty(),
                InFlightClientResolver.pendingAuthorizeUrl(withSaved("https://idp.example/oauth2/authorize", "POST")));
        assertEquals(java.util.Optional.empty(), InFlightClientResolver.pendingAuthorizeUrl(new org.springframework.mock.web.MockHttpServletRequest()));
    }

    private static org.springframework.mock.web.MockHttpServletRequest withSaved(final String url, final String method) {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getRedirectUrl()).thenReturn(url);
        when(saved.getMethod()).thenReturn(method);
        final org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest();
        request.getSession().setAttribute("SPRING_SECURITY_SAVED_REQUEST", saved);
        return request;
    }
}
