/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.i18n;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import jakarta.servlet.http.Cookie;

/**
 * Helix IAM i18n: locale resolution precedence — cookie (from a {@code ?lang=} switch) wins, else the
 * {@code Accept-Language} header is negotiated, and anything unsupported degrades to English.
 */
class LocaleResolverI18nTest {

    private final AcceptHeaderCookieLocaleResolver resolver = new AcceptHeaderCookieLocaleResolver();

    @Test
    void picksDutchFromAcceptLanguageHeaderWhenNoCookie() {
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addPreferredLocale(Locale.forLanguageTag("nl"));
        assertEquals("nl", resolver.resolveLocale(req).getLanguage());
    }

    @Test
    void picksEnglishFromAcceptLanguageHeaderWhenNoCookie() {
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addPreferredLocale(Locale.ENGLISH);
        assertEquals("en", resolver.resolveLocale(req).getLanguage());
    }

    @Test
    void unsupportedAcceptLanguageDegradesToEnglish() {
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addPreferredLocale(Locale.FRENCH);
        assertEquals("en", resolver.resolveLocale(req).getLanguage());
    }

    @Test
    void cookieWinsOverAcceptLanguageHeader() {
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addPreferredLocale(Locale.ENGLISH); // header says en ...
        req.setCookies(new Cookie(I18nConfig.LOCALE_COOKIE, "nl")); // ... cookie says nl
        assertEquals("nl", resolver.resolveLocale(req).getLanguage());
    }

    @Test
    void unsupportedCookieDegradesToEnglish() {
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.setCookies(new Cookie(I18nConfig.LOCALE_COOKIE, "fr"));
        assertEquals("en", resolver.resolveLocale(req).getLanguage());
    }

    @Test
    void supportedOrDefaultMapsByLanguageOnly() {
        assertEquals(Locale.forLanguageTag("nl"),
                AcceptHeaderCookieLocaleResolver.supportedOrDefault(Locale.forLanguageTag("nl-NL")));
        assertEquals(Locale.ENGLISH,
                AcceptHeaderCookieLocaleResolver.supportedOrDefault(Locale.forLanguageTag("en-US")));
        assertEquals(Locale.ENGLISH, AcceptHeaderCookieLocaleResolver.supportedOrDefault(null));
        assertEquals(Locale.ENGLISH, AcceptHeaderCookieLocaleResolver.supportedOrDefault(Locale.GERMAN));
    }
}
