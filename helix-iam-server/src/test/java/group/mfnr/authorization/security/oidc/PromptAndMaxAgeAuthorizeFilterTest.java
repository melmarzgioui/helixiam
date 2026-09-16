package group.mfnr.authorization.security.oidc;

import group.mfnr.authorization.security.session.AuthTimeStamper;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P2: OIDC {@code prompt}/{@code max_age} semantics at the authorize endpoint — silent SSO
 * ({@code prompt=none}), forced re-auth ({@code prompt=login}/expired {@code max_age}), with an
 * open-redirect guard before any error redirect.
 */
class PromptAndMaxAgeAuthorizeFilterTest {

    private static final long NOW = 1_782_600_000L;
    private static final String REDIRECT = "https://app.example/cb";

    private final RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
    private final AuthTimeStamper stamper = new AuthTimeStamper(); // read() needs no clock
    // Realm max-lifetime is exercised separately; here the resolver returns null (no realm in context).
    private final group.mfnr.authorization.security.realm.RealmSettingsResolver realmSettings =
            mock(group.mfnr.authorization.security.realm.RealmSettingsResolver.class);
    private final PromptAndMaxAgeAuthorizeFilter filter =
            new PromptAndMaxAgeAuthorizeFilter(clients, stamper, realmSettings, () -> NOW);
    private final FilterChain chain = mock(FilterChain.class);

    @BeforeEach
    void registerClient() {
        final RegisteredClient rc = RegisteredClient.withId("1").clientId("app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT).build();
        when(clients.findByClientId("app")).thenReturn(rc);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private MockHttpServletRequest authorize(final String query) {
        final MockHttpServletRequest req = new MockHttpServletRequest("GET", "/oauth2/authorize");
        req.setServletPath("/oauth2/authorize");
        for (final String pair : query.split("&")) {
            final String[] kv = pair.split("=", 2);
            req.setParameter(kv[0], kv.length > 1 ? kv[1] : "");
        }
        return req;
    }

    private void authenticate(final Long authTime) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("alice", "x", AuthorityUtils.NO_AUTHORITIES));
    }

    @Test
    void promptNone_withValidSession_passesThrough() throws Exception {
        authenticate(NOW);
        final MockHttpServletRequest req = authorize("client_id=app&redirect_uri=" + REDIRECT + "&prompt=none&state=s1");
        req.getSession(true).setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, NOW);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        verify(chain).doFilter(req, res);
    }

    @Test
    void promptNone_withoutSession_redirectsLoginRequired_andDoesNotInvokeChain() throws Exception {
        final MockHttpServletRequest req = authorize("client_id=app&redirect_uri=" + REDIRECT + "&prompt=none&state=s1");
        final MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        assertEquals(302, res.getStatus());
        assertTrue(res.getRedirectedUrl().startsWith(REDIRECT + "?error=login_required"), res.getRedirectedUrl());
        assertTrue(res.getRedirectedUrl().contains("state=s1"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void promptNone_withUnregisteredRedirectUri_failsClosed_noOpenRedirect() throws Exception {
        final MockHttpServletRequest req = authorize("client_id=app&redirect_uri=https://evil.example/x&prompt=none");
        final MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        assertEquals(400, res.getStatus());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void promptLogin_withSession_clearsAuthentication_thenPassesThrough() throws Exception {
        authenticate(NOW);
        final MockHttpServletRequest req = authorize("client_id=app&redirect_uri=" + REDIRECT + "&prompt=login");
        req.getSession(true).setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, NOW);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        org.junit.jupiter.api.Assertions.assertNull(SecurityContextHolder.getContext().getAuthentication(),
                "prompt=login forces re-auth by clearing the session authentication");
        verify(chain).doFilter(req, res);
    }

    @Test
    void maxAgeExceeded_forcesReauth() throws Exception {
        authenticate(NOW);
        final MockHttpServletRequest req = authorize("client_id=app&redirect_uri=" + REDIRECT + "&max_age=10");
        req.getSession(true).setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, NOW - 100); // 100s old > 10s
        final MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        org.junit.jupiter.api.Assertions.assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain).doFilter(req, res);
    }

    @Test
    void freshMaxAge_passesThroughWithoutClearing() throws Exception {
        authenticate(NOW);
        final MockHttpServletRequest req = authorize("client_id=app&redirect_uri=" + REDIRECT + "&max_age=3600");
        req.getSession(true).setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, NOW - 5); // 5s old < 3600s
        final MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        org.junit.jupiter.api.Assertions.assertEquals("alice",
                SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        verify(chain).doFilter(req, res);
    }
}
