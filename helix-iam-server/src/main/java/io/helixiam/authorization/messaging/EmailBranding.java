/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import java.util.regex.Pattern;

/**
 * The brand an email is sent under: a name, an optional logo, the colours of the email (the theme's light palette:
 * the button colour and the text on it, the page background, the card, text, muted text and borders), the footer text
 * and the legal links. Unsafe or missing values fall back to safe defaults (the HelixIAM look), so nothing from
 * configuration can break out of the email markup: colours must be {@code #RRGGBB}, links {@code https:}, and the logo
 * an absolute {@code https:} URL (or {@code http:} for an asset on the IdP's own base URL, e.g. a local deployment).
 *
 * @param color      the button / link colour (the theme's {@code primary})
 * @param onColor    text on {@code color} (the theme's {@code surfaceRaised})
 * @param footerText the footer line; null shows "Sent by {name}."
 */
public record EmailBranding(String name, String logoUrl, String color, String onColor, String background, String card,
                            String ink, String inkMuted, String border, String footerText, String privacyUrl,
                            String termsUrl, String supportUrl) {

    public static final String DEFAULT_NAME = "HelixIAM";
    public static final String DEFAULT_COLOR = "#2f6b52";
    static final String DEFAULT_ON_COLOR = "#ffffff";
    static final String DEFAULT_BACKGROUND = "#f6f1e9";
    static final String DEFAULT_CARD = "#ffffff";
    static final String DEFAULT_INK = "#1f2a24";
    static final String DEFAULT_INK_MUTED = "#7a7468";
    static final String DEFAULT_BORDER = "#e6dfd3";
    private static final Pattern COLOR = Pattern.compile("#[0-9a-fA-F]{6}");
    private static final Pattern HTTPS_URL = Pattern.compile("https://[^\\s\"'<>()\\\\]+");
    private static final Pattern HTTP_URL = Pattern.compile("https?://[^\\s\"'<>()\\\\]+");

    public EmailBranding {
        name = name == null || name.isBlank() ? DEFAULT_NAME : name.trim();
        logoUrl = logoUrl != null && HTTP_URL.matcher(logoUrl.trim()).matches() ? logoUrl.trim() : null;
        color = color(color, DEFAULT_COLOR);
        onColor = color(onColor, DEFAULT_ON_COLOR);
        background = color(background, DEFAULT_BACKGROUND);
        card = color(card, DEFAULT_CARD);
        ink = color(ink, DEFAULT_INK);
        inkMuted = color(inkMuted, DEFAULT_INK_MUTED);
        border = color(border, DEFAULT_BORDER);
        footerText = footerText == null || footerText.isBlank() ? null : footerText.strip();
        privacyUrl = https(privacyUrl);
        termsUrl = https(termsUrl);
        supportUrl = https(supportUrl);
    }

    /** A brand with only a name, an (https) logo and a button colour; everything else is the HelixIAM default. */
    public EmailBranding(final String name, final String logoUrl, final String color) {
        this(name, https(logoUrl), color, null, null, null, null, null, null, null, null, null, null);
    }

    /**
     * Item 4: the name to show users for {@code realmId}: this brand's name (the organization in context, else the
     * realm's display name), or {@code realmId} when there is neither (never "HelixIAM" for a customer's realm).
     */
    public String nameOr(final String realmId) {
        return DEFAULT_NAME.equals(name) && realmId != null && !realmId.isBlank() ? realmId : name;
    }

    public static EmailBranding helixIam() {
        return new EmailBranding(DEFAULT_NAME, null, DEFAULT_COLOR);
    }

    private static String color(final String value, final String fallback) {
        return value != null && COLOR.matcher(value.trim()).matches() ? value.trim() : fallback;
    }

    private static String https(final String url) {
        return url != null && HTTPS_URL.matcher(url.trim()).matches() ? url.trim() : null;
    }
}
