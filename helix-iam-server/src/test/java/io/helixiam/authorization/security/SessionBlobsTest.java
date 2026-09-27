/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.testsupport.LogCapture;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.servlet.FlashMap;

import javax.management.BadAttributeValueExpException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item 1: the queue session store keeps every attribute a sign-in and the account console put in the session, and a
 * session it has to drop is logged by class name (never silently, never with its contents).
 */
class SessionBlobsTest {

    private static final String FLASH_MAPS = "org.springframework.web.servlet.support.SessionFlashMapManager.FLASH_MAPS";

    @Test
    void aFlashMapFromARedirect_survivesTheStore() {
        // What RedirectAttributes leaves in the session: FlashMap keeps its target parameters in a LinkedMultiValueMap.
        final FlashMap flash = new FlashMap();
        flash.put("status", "password-changed");
        flash.setTargetRequestPath("/realms/monthfold/account/security");
        flash.addTargetRequestParam("tab", "password");
        flash.startExpirationPeriod(180);
        final Map<String, Object> attributes = new HashMap<>();
        attributes.put(FLASH_MAPS, new ArrayList<>(List.of(flash)));
        attributes.put("SPRING_SECURITY_CONTEXT", signedIn());

        final Map<String, Object> back = roundTripKept(attributes);

        assertThat(back).containsKeys(FLASH_MAPS, "SPRING_SECURITY_CONTEXT");
        final FlashMap restored = (FlashMap) ((List<?>) back.get(FLASH_MAPS)).get(0);
        assertThat(restored.get("status")).isEqualTo("password-changed");
        assertThat(restored.getTargetRequestParams().getFirst("tab")).isEqualTo("password");
    }

    @Test
    void theSignInJourneysAttributes_surviveTheStore() {
        final MockHttpServletRequest authorize = new MockHttpServletRequest("GET", "/realms/monthfold/oauth2/authorize");
        authorize.setServerName("auth.monthfold.com");
        authorize.setQueryString("response_type=code&client_id=web&scope=openid");
        authorize.addParameter("response_type", "code");
        authorize.addParameter("client_id", "web");
        authorize.addHeader("Accept-Language", "nl-NL");
        authorize.addHeader("User-Agent", "Mozilla/5.0");
        authorize.setCookies(new Cookie("theme", "dark"));
        authorize.addPreferredLocale(Locale.forLanguageTag("nl-NL"));

        final Map<String, Object> attributes = new HashMap<>();
        attributes.put("SPRING_SECURITY_SAVED_REQUEST", new DefaultSavedRequest(authorize));
        attributes.put("SPRING_SECURITY_CONTEXT", signedIn());
        attributes.put("org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN",
                new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "token"));
        attributes.put("org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE", Locale.forLanguageTag("nl-NL"));
        attributes.put("HELIX_AUTH_TIME", 1_790_000_000L);
        attributes.put("HELIX_SID", "sid-1");
        attributes.put("HELIX_SESSIONS_KEPT_AT", 1_790_000_000_000L);

        final Map<String, Object> back = roundTripKept(attributes);

        assertThat(back).containsOnlyKeys(attributes.keySet());
        assertThat(((DefaultSavedRequest) back.get("SPRING_SECURITY_SAVED_REQUEST")).getRedirectUrl())
                .contains("/realms/monthfold/oauth2/authorize");
    }

    @Test
    void aRejectedSession_isLoggedByClassName_withoutItsContents() {
        final Map<String, Object> attributes = new HashMap<>();
        attributes.put("gadget", new BadAttributeValueExpException("secret-session-content"));

        final Map<String, Object> back;
        try (LogCapture log = LogCapture.of(SessionBlobs.class)) {
            back = roundTrip(attributes);

            assertThat(back).isEmpty();
            assertThat(log.text()).contains("javax.management.BadAttributeValueExpException")
                    .doesNotContain("secret-session-content");
        }
    }

    /** Serializes and reads back {@code attributes}; a round trip that the store had to drop fails with its log line. */
    private static Map<String, Object> roundTrip(final Map<String, Object> attributes) {
        return SessionBlobs.deserialize(SessionBlobs.serialize(attributes));
    }

    private static Map<String, Object> roundTripKept(final Map<String, Object> attributes) {
        try (LogCapture log = LogCapture.of(SessionBlobs.class)) {
            final Map<String, Object> back = roundTrip(attributes);
            assertThat(log.text()).as("the store dropped the session").doesNotContain("dropped");
            return back;
        }
    }

    private static SecurityContextImpl signedIn() {
        final UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                User.withUsername("ada").password("").authorities("ROLE_user").build(), null,
                List.of(new SimpleGrantedAuthority("ROLE_user")));
        authentication.setDetails(new WebAuthenticationDetails("127.0.0.1", "session-id"));
        return new SecurityContextImpl(authentication);
    }
}
