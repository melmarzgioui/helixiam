/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** A3: a freshly issued code is bound to the browser session's sid + auth_time, exactly once. */
class SsoSessionBindingAuthorizationServiceTest {

    private final AtomicReference<OAuth2Authorization> saved = new AtomicReference<>();
    private final OAuth2AuthorizationService store = mock(OAuth2AuthorizationService.class,
            invocation -> {
                if ("save".equals(invocation.getMethod().getName())) {
                    saved.set(invocation.getArgument(0));
                }
                return null;
            });
    private final SsoSessionBindingAuthorizationService service = new SsoSessionBindingAuthorizationService(store);

    @AfterEach
    void reset() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void codeIssuedInABrowserSession_carriesTheSessionSidAndAuthTime() {
        final MockHttpServletRequest request = browserRequest("sid-1", 1_700_000_000L);

        service.save(withCode(false));

        assertThat(saved.get().<String>getAttribute(SsoSessionBindingAuthorizationService.SID_ATTRIBUTE)).isEqualTo("sid-1");
        assertThat(saved.get().<Long>getAttribute(SsoSessionBindingAuthorizationService.AUTH_TIME_ATTRIBUTE))
                .isEqualTo(1_700_000_000L);
        assertThat(saved.get().<String>getAttribute(SsoSessionBindingAuthorizationService.HTTP_SESSION_ATTRIBUTE))
                .isEqualTo(request.getSession(false).getId());
    }

    @Test
    void alreadyBoundOrExchanged_isNotRebound() {
        browserRequest("sid-2", 1_700_000_100L);
        final OAuth2Authorization bound = OAuth2Authorization.from(withCode(false))
                .attribute(SsoSessionBindingAuthorizationService.SID_ATTRIBUTE, "sid-1").build();

        service.save(bound);
        assertThat(saved.get().<String>getAttribute(SsoSessionBindingAuthorizationService.SID_ATTRIBUTE)).isEqualTo("sid-1");

        service.save(withCode(true));
        assertThat(saved.get().<String>getAttribute(SsoSessionBindingAuthorizationService.SID_ATTRIBUTE)).isNull();
    }

    @Test
    void outsideARequest_savesUnchanged() {
        final OAuth2Authorization authorization = withCode(false);
        service.save(authorization);
        verify(store).save(authorization);
    }

    /** Task 3: a federated login's brokered level of assurance (stashed as {@code HELIX_ACR}) is bound too. */
    @Test
    void codeIssuedInASessionCarryingAnAcr_bindsItTooAlongsideSidAndAuthTime() {
        final MockHttpServletRequest request = browserRequest("sid-3", 1_700_000_200L);
        request.getSession(false).setAttribute(AuthTimeStamper.ACR_SESSION_ATTRIBUTE, "http://eidas.europa.eu/LoA/substantial");

        service.save(withCode(false));

        assertThat(saved.get().<String>getAttribute(SsoSessionBindingAuthorizationService.ACR_ATTRIBUTE))
                .isEqualTo("http://eidas.europa.eu/LoA/substantial");
    }

    @Test
    void codeIssuedInASessionWithNoAcr_bindsNoAcrAttribute() {
        browserRequest("sid-4", 1_700_000_300L);

        service.save(withCode(false));

        assertThat(saved.get().<String>getAttribute(SsoSessionBindingAuthorizationService.ACR_ATTRIBUTE)).isNull();
    }

    // ------------------------------------------------------------------ verify-only: verified_claims

    private static final String CLAIMS = "{\"claims\":{\"age_over_18\":true}}";

    /** The pending release for client "web" and the request {@link #withRequest} carries. */
    private static String pendingFor(final String clientId, final String state, final Instant expires) {
        return PendingVerifiedClaims.wrap(CLAIMS, clientId,
                PendingVerifiedClaims.requestHash(clientId, state, "n-1", "https://app.example/cb"), expires);
    }

    /** A code being issued for client "web", request (state, nonce n-1), with {@code scopes} authorized. */
    private static OAuth2Authorization withRequest(final String state, final java.util.Set<String> scopes) {
        final org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest request =
                org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri("https://idp.example/oauth2/authorize").clientId("web")
                        .redirectUri("https://app.example/cb").state(state).scopes(scopes)
                        .additionalParameters(java.util.Map.of("nonce", "n-1")).build();
        return OAuth2Authorization.from(withCode(false)).authorizedScopes(scopes)
                .attribute(org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class.getName(),
                        request).build();
    }

    private String bound() {
        return saved.get().getAttribute(SsoSessionBindingAuthorizationService.VERIFIED_CLAIMS_ATTRIBUTE);
    }

    @Test
    void verifiedClaims_bindToTheCodeOfTheVerySameRequest_withTheScope_once() {
        final MockHttpServletRequest request = browserRequest("sid-5", 1_700_000_400L);
        request.getSession(false).setAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE,
                pendingFor("web", "st-1", Instant.now().plusSeconds(300)));

        service.save(withRequest("st-1", java.util.Set.of("openid", "verified_claims")));
        assertThat(bound()).isEqualTo(CLAIMS);
        assertThat(request.getSession(false).getAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE)).isNull();

        service.save(withRequest("st-1", java.util.Set.of("openid", "verified_claims")));
        assertThat(bound()).as("released once").isNull();
    }

    @Test
    void verifiedClaims_areDropped_forAnotherRequestOrClient_afterTheTtl_orWithoutTheScope() {
        for (final OAuth2Authorization other : java.util.List.of(
                withRequest("st-OTHER", java.util.Set.of("openid", "verified_claims")),
                withRequest("st-1", java.util.Set.of("openid")))) {
            final MockHttpServletRequest request = browserRequest("sid-6", 1_700_000_500L);
            request.getSession(false).setAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE,
                    pendingFor("web", "st-1", Instant.now().plusSeconds(300)));
            service.save(other);
            assertThat(bound()).isNull();
            assertThat(request.getSession(false).getAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE))
                    .as("dropped on mismatch").isNull();
        }
        final MockHttpServletRequest otherClient = browserRequest("sid-7", 1_700_000_600L);
        otherClient.getSession(false).setAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE,
                pendingFor("bank", "st-1", Instant.now().plusSeconds(300)));
        service.save(withRequest("st-1", java.util.Set.of("openid", "verified_claims")));
        assertThat(bound()).isNull();

        final MockHttpServletRequest expired = browserRequest("sid-8", 1_700_000_700L);
        expired.getSession(false).setAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE,
                pendingFor("web", "st-1", Instant.now().minusSeconds(1)));
        service.save(withRequest("st-1", java.util.Set.of("openid", "verified_claims")));
        assertThat(bound()).isNull();
    }

    @Test
    void anAuthorizationRemovedInTheBrowser_dropsThePendingClaims_consentDenied() {
        final MockHttpServletRequest request = browserRequest("sid-9", 1_700_000_800L);
        request.getSession(false).setAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE,
                pendingFor("web", "st-1", Instant.now().plusSeconds(300)));
        service.remove(withRequest("st-1", java.util.Set.of("openid")));
        assertThat(request.getSession(false).getAttribute(AuthTimeStamper.VERIFIED_CLAIMS_SESSION_ATTRIBUTE)).isNull();
    }

    @Test
    void theExchangedAuthorization_isStoredWithoutTheVerifiedClaims() {
        final OAuth2Authorization exchanged = OAuth2Authorization.from(withCode(true))
                .attribute(SsoSessionBindingAuthorizationService.VERIFIED_CLAIMS_ATTRIBUTE, CLAIMS).build();
        service.save(exchanged);
        assertThat(bound()).isNull();
    }

    private static MockHttpServletRequest browserRequest(final String sid, final long authTime) {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute(AuthTimeStamper.HELIX_SID, sid);
        request.getSession().setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, authTime);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return request;
    }

    private static OAuth2Authorization withCode(final boolean exchanged) {
        final RegisteredClient client = RegisteredClient.withId("c1").clientId("web")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://app.example/cb").build();
        final Instant now = Instant.now();
        final OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .principalName("user-1")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new OAuth2AuthorizationCode("code", now, now.plusSeconds(60)));
        if (exchanged) {
            builder.accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "at", now, now.plusSeconds(300)));
        }
        return builder.build();
    }
}
