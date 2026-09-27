/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The starter message templates every realm gets (seeded in English, editable afterwards), and their Dutch
 * translations. Item 3: a template the realm has not edited (its subject and body are still the English default) is
 * sent in Dutch to a user whose language is Dutch; an edited template is sent as written. SMS and push are plain text;
 * the email templates are HTML, rendered in the realm's branded layout with a plain-text part derived from them.
 */
public final class DefaultMessageTemplates {

    /** Account console: the confirmation link sent to a changed email address ({@code {{link}}}, {@code {{ttl}}}). */
    public static final String EMAIL_CHANGE_VERIFY = "email-change-verify";
    /** Account console: the notice sent to the previous address when the email address changes. */
    public static final String EMAIL_CHANGED_NOTICE = "email-changed-notice";

    private static final String MUTED = "<p style=\"color:#7a7468;font-size:13px\">";

    /** One default template: its key, channel, subject (null for SMS), body, and whether the body is HTML. */
    public record Template(String key, String channel, String subject, String body, boolean html) {
    }

    private static final List<Template> ENGLISH = List.of(
            new Template("otp-sms", "SMS", null, "{{realm}} verification code: {{code}} (valid {{ttl}}).", false),
            new Template("otp-email", "EMAIL", "Your {{realm}} verification code",
                    "<p>Hi {{user}},</p>\n<p>Your verification code is:</p>\n"
                            + "<p style=\"font-size:28px;font-weight:700;letter-spacing:6px;margin:8px 0 16px;\">{{code}}</p>\n"
                            + "<p>It expires in {{ttl}}.</p>\n" + MUTED
                            + "If you didn't request this, you can safely ignore this email.</p>", true),
            new Template("magic-link-email", "EMAIL", "Sign in to {{realm}}",
                    "<p>Hi {{user}},</p>\n<p>Use the button below to sign in to {{realm}}.</p>\n"
                            + "<p><a href=\"{{link}}\" data-button>Sign in</a></p>\n"
                            + MUTED + "If the button doesn't work, copy this link into your browser:<br>"
                            + "<a href=\"{{link}}\" style=\"color:#7a7468;word-break:break-all\">{{link}}</a></p>\n"
                            + MUTED + "This link works once and expires in {{ttl}}. "
                            + "If you didn't request it, you can safely ignore this email.</p>", true),
            new Template("verify-email", "EMAIL", "Verify your email address for {{realm}}",
                    "<p>Hi,</p>\n<p>Please confirm that {{user}} is your email address.</p>\n"
                            + "<p><a href=\"{{link}}\" data-button>Verify email address</a></p>\n"
                            + MUTED + "If the button doesn't work, copy this link into your browser:<br>"
                            + "<a href=\"{{link}}\" style=\"color:#7a7468;word-break:break-all\">{{link}}</a></p>\n"
                            + MUTED + "This link works once and expires in {{ttl}}. "
                            + "If you didn't expect this email, you can safely ignore it.</p>", true),
            new Template("push-approval", "PUSH", "Approve your sign-in",
                    "Tap to approve signing in to {{realm}}. Match this number: {{number}}.", false),
            new Template(EMAIL_CHANGE_VERIFY, "EMAIL", "Confirm your new email address",
                    "<p>Hi {{user}},</p>\n<p>You changed the email address of your {{realm}} account to this address. "
                            + "Confirm it with the button below.</p>\n"
                            + "<p><a href=\"{{link}}\" data-button>Confirm email address</a></p>\n"
                            + MUTED + "If the button doesn't work, copy this link into your browser:<br>"
                            + "<a href=\"{{link}}\" style=\"color:#7a7468;word-break:break-all\">{{link}}</a></p>\n"
                            + MUTED + "The link works once and expires in {{ttl}}. "
                            + "If you didn't change your email address, you can ignore this email.</p>", true),
            new Template(EMAIL_CHANGED_NOTICE, "EMAIL", "Your email address was changed",
                    "<p>Hi {{user}},</p>\n<p>The email address of your {{realm}} account was just changed, and this "
                            + "address will no longer receive its messages.</p>\n"
                            + MUTED + "If you didn't do this, sign in and change your "
                            + "password, or contact the service's support.</p>", true));

    private static final List<Template> DUTCH = List.of(
            new Template("otp-sms", "SMS", null, "{{realm}} verificatiecode: {{code}} (geldig {{ttl}}).", false),
            new Template("otp-email", "EMAIL", "Je verificatiecode voor {{realm}}",
                    "<p>Hoi {{user}},</p>\n<p>Je verificatiecode is:</p>\n"
                            + "<p style=\"font-size:28px;font-weight:700;letter-spacing:6px;margin:8px 0 16px;\">{{code}}</p>\n"
                            + "<p>De code verloopt over {{ttl}}.</p>\n" + MUTED
                            + "Heb je dit niet aangevraagd? Dan kun je deze e-mail negeren.</p>", true),
            new Template("magic-link-email", "EMAIL", "Inloggen bij {{realm}}",
                    "<p>Hoi {{user}},</p>\n<p>Gebruik de knop hieronder om in te loggen bij {{realm}}.</p>\n"
                            + "<p><a href=\"{{link}}\" data-button>Inloggen</a></p>\n"
                            + MUTED + "Werkt de knop niet? Kopieer dan deze link naar je browser:<br>"
                            + "<a href=\"{{link}}\" style=\"color:#7a7468;word-break:break-all\">{{link}}</a></p>\n"
                            + MUTED + "Deze link werkt één keer en verloopt over {{ttl}}. "
                            + "Heb je hem niet aangevraagd? Dan kun je deze e-mail negeren.</p>", true),
            new Template("verify-email", "EMAIL", "Bevestig je e-mailadres voor {{realm}}",
                    "<p>Hoi,</p>\n<p>Bevestig dat {{user}} jouw e-mailadres is.</p>\n"
                            + "<p><a href=\"{{link}}\" data-button>E-mailadres bevestigen</a></p>\n"
                            + MUTED + "Werkt de knop niet? Kopieer dan deze link naar je browser:<br>"
                            + "<a href=\"{{link}}\" style=\"color:#7a7468;word-break:break-all\">{{link}}</a></p>\n"
                            + MUTED + "Deze link werkt één keer en verloopt over {{ttl}}. "
                            + "Verwachtte je deze e-mail niet? Dan kun je hem negeren.</p>", true),
            new Template("push-approval", "PUSH", "Keur je aanmelding goed",
                    "Tik om inloggen bij {{realm}} goed te keuren. Controleer dit nummer: {{number}}.", false),
            new Template(EMAIL_CHANGE_VERIFY, "EMAIL", "Bevestig je nieuwe e-mailadres",
                    "<p>Hoi {{user}},</p>\n<p>Je hebt het e-mailadres van je {{realm}}-account gewijzigd in dit adres. "
                            + "Bevestig het met de knop hieronder.</p>\n"
                            + "<p><a href=\"{{link}}\" data-button>E-mailadres bevestigen</a></p>\n"
                            + MUTED + "Werkt de knop niet? Kopieer dan deze link naar je browser:<br>"
                            + "<a href=\"{{link}}\" style=\"color:#7a7468;word-break:break-all\">{{link}}</a></p>\n"
                            + MUTED + "De link werkt één keer en verloopt over {{ttl}}. "
                            + "Heb je je e-mailadres niet gewijzigd? Dan kun je deze e-mail negeren.</p>", true),
            new Template(EMAIL_CHANGED_NOTICE, "EMAIL", "Je e-mailadres is gewijzigd",
                    "<p>Hoi {{user}},</p>\n<p>Het e-mailadres van je {{realm}}-account is zojuist gewijzigd. Dit adres "
                            + "ontvangt de berichten van het account niet meer.</p>\n"
                            + MUTED + "Heb je dit niet zelf gedaan? Log dan in en wijzig je wachtwoord, "
                            + "of neem contact op met de support van de dienst.</p>", true));

    private DefaultMessageTemplates() {
    }

    /** The English defaults, the set a realm is seeded with. */
    public static List<Template> english() {
        return ENGLISH;
    }

    /** The Dutch translation of the default template {@code key}. */
    public static Optional<Template> dutch(final String key) {
        return DUTCH.stream().filter(t -> t.key().equals(key)).findFirst();
    }

    /**
     * The subject and body to send for a realm template in {@code locale}: the translation when the template is still
     * the English default and the user's language has one, else the template as stored.
     */
    public static Template localise(final String key, final String subject, final String body, final boolean html,
                                    final Locale locale) {
        final Template stored = new Template(key, null, subject, body, html);
        if (locale == null || !"nl".equals(locale.getLanguage())) {
            return stored;
        }
        final Optional<Template> english = ENGLISH.stream().filter(t -> t.key().equals(key)).findFirst();
        if (english.isEmpty() || !java.util.Objects.equals(english.get().subject(), blankToNull(subject))
                || !java.util.Objects.equals(english.get().body(), body) || english.get().html() != html) {
            return stored;
        }
        return dutch(key).orElse(stored);
    }

    /** "5 minutes" / "5 minuten", "24 hours" / "24 uur": a template's {@code {{ttl}}} in the user's language. */
    public static String minutes(final long minutes, final Locale locale) {
        final boolean nl = locale != null && "nl".equals(locale.getLanguage());
        return minutes + (nl ? (minutes == 1 ? " minuut" : " minuten") : (minutes == 1 ? " minute" : " minutes"));
    }

    /** See {@link #minutes}. */
    public static String hours(final long hours, final Locale locale) {
        final boolean nl = locale != null && "nl".equals(locale.getLanguage());
        return hours + (nl ? " uur" : (hours == 1 ? " hour" : " hours"));
    }

    private static String blankToNull(final String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
