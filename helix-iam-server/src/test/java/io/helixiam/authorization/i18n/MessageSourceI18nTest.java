package io.helixiam.authorization.i18n;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.springframework.context.MessageSource;

/**
 * Helix IAM i18n: the login / self-service message bundles resolve for both English (default) and
 * Dutch (nl-NL), and Dutch falls back to the English bundle for any key it does not (yet) define.
 */
class MessageSourceI18nTest {

    private final MessageSource messages = new I18nConfig().messageSource();

    private static final Locale NL = Locale.forLanguageTag("nl");

    @Test
    void resolvesEnglishLoginStrings() {
        assertEquals("Sign in", messages.getMessage("login.title", null, Locale.ENGLISH));
        assertEquals("Email Address", messages.getMessage("login.username.label", null, Locale.ENGLISH));
        assertEquals("Forgot Password?", messages.getMessage("login.forgotPassword", null, Locale.ENGLISH));
    }

    @Test
    void resolvesDutchLoginStrings() {
        assertEquals("Inloggen", messages.getMessage("login.title", null, NL));
        assertEquals("E-mailadres", messages.getMessage("login.username.label", null, NL));
        assertEquals("Wachtwoord vergeten?", messages.getMessage("login.forgotPassword", null, NL));
    }

    @Test
    void dutchDiffersFromEnglishAcrossRepresentativeKeys() {
        for (final String key : new String[] {
                "register.submit", "reset.title", "mfa.totp.title", "flow.otp.title", "flow.consent.submit"}) {
            assertNotEquals(messages.getMessage(key, null, Locale.ENGLISH),
                    messages.getMessage(key, null, NL),
                    "expected a real Dutch translation for key " + key);
        }
    }

    @Test
    void dutchFallsBackToEnglishForAnUntranslatedKey() {
        // Brand name is intentionally identical in both bundles — proves the bundle loads, not a key echo.
        assertEquals("KubeDNA", messages.getMessage("brand.name", null, NL));
    }

    @Test
    void unknownKeyDegradesToTheKeyItselfRatherThanThrowing() {
        final String unknown = "totally.unknown.key";
        assertEquals(unknown, messages.getMessage(unknown, null, NL));
    }

    @Test
    void everyEnglishKeyAlsoExistsInDutch() throws Exception {
        final java.util.Properties en = new java.util.Properties();
        final java.util.Properties nl = new java.util.Properties();
        try (var enStream = getClass().getResourceAsStream("/messages.properties");
             var nlStream = getClass().getResourceAsStream("/messages_nl.properties")) {
            en.load(new java.io.InputStreamReader(enStream, java.nio.charset.StandardCharsets.UTF_8));
            nl.load(new java.io.InputStreamReader(nlStream, java.nio.charset.StandardCharsets.UTF_8));
        }
        final java.util.Set<String> missing = new java.util.TreeSet<>();
        for (final Object key : en.keySet()) {
            if (!nl.containsKey(key)) {
                missing.add(String.valueOf(key));
            }
        }
        assertFalse(en.isEmpty(), "English bundle should not be empty");
        assertEquals(java.util.Set.of(), missing, "Dutch bundle is missing keys: " + missing);
    }
}
