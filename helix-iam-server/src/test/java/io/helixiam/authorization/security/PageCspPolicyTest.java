/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Structured theming §6: the page CSP — no inline styles, per-realm image origins, CAPTCHA hosts only when enabled. */
class PageCspPolicyTest {

    @Test
    void withoutARealmTheme_imagesAreSelfAndDataOnly_andNoInlineStylesAnywhere() {
        final String csp = PageCspPolicy.build(Set.of(), null, false);
        assertThat(csp).contains("style-src 'self';", "img-src 'self' data:;", "script-src 'self';", "frame-src 'none';",
                "connect-src 'self';", "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'")
                .doesNotContain("unsafe-inline").doesNotContain("https:;");
    }

    @Test
    void theRealmsOriginsAreListed_sorted_andAnythingThatIsNotAnHttpsOriginIsDropped() {
        final String csp = PageCspPolicy.build(List.of("https://cdn.b.example", "https://cdn.a.example:8443",
                "http://plain.example", "https://x.example/path", "*", "https: 'unsafe-inline'"), null, false);
        assertThat(csp).contains("img-src 'self' data: https://cdn.a.example:8443 https://cdn.b.example;")
                .doesNotContain("plain.example").doesNotContain("/path").doesNotContain("unsafe-inline");
    }

    @Test
    void captchaHostsOnlyForTheEnabledProvider_andSamlPagesMayPostToHttps() {
        assertThat(PageCspPolicy.build(Set.of(), "turnstile", false))
                .contains("script-src 'self' https://challenges.cloudflare.com;",
                        "frame-src https://challenges.cloudflare.com;",
                        "connect-src 'self' https://challenges.cloudflare.com;").doesNotContain("google");
        assertThat(PageCspPolicy.build(Set.of(), "recaptcha", false))
                .contains("script-src 'self' https://www.google.com https://www.gstatic.com;",
                        "frame-src https://www.google.com;").doesNotContain("cloudflare");
        assertThat(PageCspPolicy.build(Set.of(), null, true)).endsWith("form-action 'self' https:");
    }

    // ------------------------------------------------------------------------------------------------
    // A1: form-action allows the pending authorization request's registered redirect origins
    // ------------------------------------------------------------------------------------------------

    @Test
    void formAction_listsTheGivenRedirectOrigins_afterSelf() {
        final String csp = PageCspPolicy.build(Set.of(), null, false,
                List.of("https://app.monthfold.com", "http://127.0.0.1:52100"));
        assertThat(csp).endsWith("form-action 'self' http://127.0.0.1:52100 https://app.monthfold.com");
    }

    @Test
    void formActionSource_isTheOriginOfARedirectUri_orASchemeForNativeApps_andNothingUnsafe() {
        assertThat(PageCspPolicy.formActionSource("https://app.monthfold.com/auth/callback?x=1#f"))
                .isEqualTo("https://app.monthfold.com");
        assertThat(PageCspPolicy.formActionSource("https://APP.monthfold.com:443/cb")).isEqualTo("https://app.monthfold.com");
        assertThat(PageCspPolicy.formActionSource("https://app.monthfold.com:8443/cb")).isEqualTo("https://app.monthfold.com:8443");
        assertThat(PageCspPolicy.formActionSource("http://127.0.0.1:52100/auth/callback")).isEqualTo("http://127.0.0.1:52100");
        assertThat(PageCspPolicy.formActionSource("http://[::1]:8080/cb")).isEqualTo("http://[::1]:8080");
        assertThat(PageCspPolicy.formActionSource("com.monthfold.app:/oauth2redirect")).isEqualTo("com.monthfold.app:");
        assertThat(PageCspPolicy.formActionSource("javascript:alert(1)")).isNull();
        assertThat(PageCspPolicy.formActionSource("data:text/html,x")).isNull();
        assertThat(PageCspPolicy.formActionSource("https://a.example; script-src *")).isNull();
        assertThat(PageCspPolicy.formActionSource("https://*.example/cb")).isNull();
        assertThat(PageCspPolicy.formActionSource("https://user@a.example/cb")).isEqualTo("https://a.example");
        assertThat(PageCspPolicy.formActionSource("/relative")).isNull();
        assertThat(PageCspPolicy.formActionSource(null)).isNull();
    }

    @Test
    void formAction_dropsAnythingThatIsNotASourceExpression() {
        final String csp = PageCspPolicy.build(Set.of(), null, false,
                List.of("https://ok.example", "https://x.example; script-src *", "*", "'unsafe-inline'"));
        assertThat(csp).endsWith("form-action 'self' https://ok.example").doesNotContain("unsafe-inline")
                .doesNotContain("script-src *");
    }

    @AfterEach
    void clearRealm() {
        RealmContextHolder.clear();
    }

    @Test
    void thePendingAuthorizationRequest_inTheSession_addsItsClientsRedirectOrigins() {
        final PageCspPolicy policy = policyWith(client());
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest authorize = pageRequest("/oauth2/authorize", session);
        authorize.setParameter("client_id", "web");
        authorize.setParameter("redirect_uri", "https://app.monthfold.com/auth/callback");
        new HttpSessionRequestCache().saveRequest(authorize, new MockHttpServletResponse());

        RealmContextHolder.set("monthfold");
        final String csp = policy.policy(pageRequest("/login", session), false);

        assertThat(csp).endsWith("form-action 'self' https://app.monthfold.com https://m.monthfold.com:8443")
                .doesNotContain("logged-out.monthfold.com");
    }

    @Test
    void theConsentPage_addsTheOriginsOfTheClientInItsQuery() {
        final PageCspPolicy policy = policyWith(client());
        final MockHttpServletRequest consent = pageRequest("/oauth2/consent", new MockHttpSession());
        consent.setParameter("client_id", "web");
        RealmContextHolder.set("monthfold");
        assertThat(policy.policy(consent, false)).contains("form-action 'self' https://app.monthfold.com");
    }

    @Test
    void aLogoutPage_addsThePostLogoutOrigins() {
        final PageCspPolicy policy = policyWith(client());
        final MockHttpServletRequest logout = pageRequest("/connect/logout", new MockHttpSession());
        logout.setParameter("client_id", "web");
        RealmContextHolder.set("monthfold");
        assertThat(policy.policy(logout, false)).endsWith("form-action 'self' https://logged-out.monthfold.com");
    }

    @Test
    void noPendingRequest_anUnknownClient_orNoRealm_keepFormActionSelf() {
        final PageCspPolicy policy = policyWith(client());
        RealmContextHolder.set("monthfold");
        assertThat(policy.policy(pageRequest("/login", new MockHttpSession()), false)).endsWith("form-action 'self'");
        final MockHttpServletRequest consent = pageRequest("/oauth2/consent", new MockHttpSession());
        consent.setParameter("client_id", "nobody");
        assertThat(policy.policy(consent, false)).endsWith("form-action 'self'");
        RealmContextHolder.clear();
        consent.setParameter("client_id", "web");
        assertThat(policy.policy(consent, false)).endsWith("form-action 'self'");
    }

    private static MockHttpServletRequest pageRequest(final String servletPath, final MockHttpSession session) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/realms/monthfold" + servletPath);
        request.setContextPath("/realms/monthfold");
        request.setServletPath(servletPath);
        request.setSession(session);
        return request;
    }

    private static RegisteredClient client() {
        return RegisteredClient.withId("1").clientId("web").clientSecret("{noop}s")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://app.monthfold.com/auth/callback")
                .redirectUri("https://m.monthfold.com:8443/cb")
                .postLogoutRedirectUri("https://logged-out.monthfold.com/")
                .scope("openid").build();
    }

    private static PageCspPolicy policyWith(final RegisteredClient client) {
        final StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("clients", new InMemoryRegisteredClientRepository(client));
        return new PageCspPolicy(beans.getBeanProvider(io.helixiam.authorization.theme.ThemeService.class),
                beans.getBeanProvider(io.helixiam.authorization.security.captcha.CaptchaService.class),
                beans.getBeanProvider(io.helixiam.authorization.federation.IdentityProviderRegistry.class),
                beans.getBeanProvider(RegisteredClientRepository.class));
    }

    @Test
    void samlPages_keepTheirHttpsFormAction_whateverTheRedirectOrigins() {
        assertThat(PageCspPolicy.build(Set.of(), null, true, List.of("https://app.example")))
                .endsWith("form-action 'self' https:");
    }

    @Test
    void theFrontChannelLogoutPage_mayFrameExactlyTheClientsLogoutOrigins() {
        final PageCspPolicy policy = policyWith(client());
        RealmContextHolder.set("monthfold");
        final String csp = policy.withFrames(pageRequest("/connect/logout", new MockHttpSession()), List.of(
                "https://app.monthfold.com/auth/fc?iss=x&sid=y", "https://b.example:8443/fc", "javascript:alert(1)",
                "https://evil.example/x; script-src *", "custom-app:/fc"));
        assertThat(csp).contains("frame-src https://app.monthfold.com https://b.example:8443; ")
                .doesNotContain("javascript").doesNotContain("evil").doesNotContain("custom-app")
                .contains("style-src 'self'; ").contains("script-src 'self'; ");
        assertThat(policy.withFrames(pageRequest("/connect/logout", new MockHttpSession()), List.of()))
                .contains("frame-src 'none'; ");
    }
}
