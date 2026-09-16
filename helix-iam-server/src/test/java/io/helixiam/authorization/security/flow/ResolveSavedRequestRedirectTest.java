/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P1: after login completes, resume the originating {@code /oauth2/authorize} request that
 * Spring Security cached before bouncing the user to {@code /login} — so the code/token comes back for the
 * client that started the flow, not the dashboard. The saved request's redirect URL is already
 * realm-prefixed, so it is returned verbatim.
 */
class ResolveSavedRequestRedirectTest {

    private static final String SAVED = "https://idp.example/realms/master/oauth2/authorize?client_id=spa-app&response_type=code";
    private static final String FALLBACK = "https://dashboard.example/";

    private final RequestCache cache = mock(RequestCache.class);
    private final ResolveSavedRequestRedirect resolver = new ResolveSavedRequestRedirect(cache);
    private final HttpServletRequest req = mock(HttpServletRequest.class);
    private final HttpServletResponse res = mock(HttpServletResponse.class);

    @Test
    void returnsSavedUrlVerbatim_andConsumesTheSavedRequest() {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getRedirectUrl()).thenReturn(SAVED);
        when(cache.getRequest(req, res)).thenReturn(saved);

        final String url = resolver.resumeUrlOrDefault(req, res, FALLBACK);

        assertEquals(SAVED, url, "the realm-prefixed authorize URL is returned unmodified");
        verify(cache).removeRequest(req, res);
    }

    @Test
    void returnsFallback_andDoesNotConsume_whenThereIsNoSavedRequest() {
        when(cache.getRequest(req, res)).thenReturn(null);

        assertEquals(FALLBACK, resolver.resumeUrlOrDefault(req, res, FALLBACK));
        verify(cache, never()).removeRequest(any(), any());
    }

    @Test
    void redirectView_prefixesWithRedirectColon() {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getRedirectUrl()).thenReturn(SAVED);
        when(cache.getRequest(req, res)).thenReturn(saved);

        assertEquals("redirect:" + SAVED, resolver.redirectView(req, res, FALLBACK));
    }

    @Test
    void sendRedirect_writesTheResumeUrlToTheResponse() throws Exception {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getRedirectUrl()).thenReturn(SAVED);
        when(cache.getRequest(req, res)).thenReturn(saved);

        resolver.sendRedirect(req, res, FALLBACK);

        verify(res).sendRedirect(SAVED);
    }
}
