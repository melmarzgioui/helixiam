/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import java.util.regex.Pattern;

/**
 * The brand an email is sent under: a name, an optional logo (https only) and a colour (#RRGGBB). Unsafe or missing
 * values fall back to safe defaults, so nothing from configuration can break out of the email markup.
 */
public record EmailBranding(String name, String logoUrl, String color) {

    public static final String DEFAULT_NAME = "HelixIAM";
    public static final String DEFAULT_COLOR = "#2f6b52";
    private static final Pattern COLOR = Pattern.compile("#[0-9a-fA-F]{6}");
    private static final Pattern HTTPS_URL = Pattern.compile("https://[^\\s\"'<>()\\\\]+");

    public EmailBranding {
        name = name == null || name.isBlank() ? DEFAULT_NAME : name.trim();
        logoUrl = logoUrl != null && HTTPS_URL.matcher(logoUrl.trim()).matches() ? logoUrl.trim() : null;
        color = color != null && COLOR.matcher(color.trim()).matches() ? color.trim() : DEFAULT_COLOR;
    }

    public static EmailBranding helixIam() {
        return new EmailBranding(DEFAULT_NAME, null, DEFAULT_COLOR);
    }
}
