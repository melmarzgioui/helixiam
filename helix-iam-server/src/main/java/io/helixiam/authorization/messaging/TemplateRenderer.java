/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helix IAM notifications (N3): renders a message template by substituting {@code {{variable}}} placeholders
 * (whitespace-tolerant) with supplied values. Unknown placeholders render blank so a template never leaks a
 * raw {@code {{...}}} token to a user. Pure + side-effect-free.
 */
public final class TemplateRenderer {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{\\s*([\\w.-]+)\\s*}}");

    private TemplateRenderer() {
    }

    /** Substitute {@code {{var}}} in {@code template} from {@code variables}; null template → empty string. */
    public static String render(final String template, final Map<String, String> variables) {
        if (template == null || template.isEmpty()) {
            return "";
        }
        final Map<String, String> vars = variables == null ? Map.of() : variables;
        final Matcher m = PLACEHOLDER.matcher(template);
        final StringBuilder out = new StringBuilder();
        while (m.find()) {
            final String value = vars.getOrDefault(m.group(1), "");
            m.appendReplacement(out, Matcher.quoteReplacement(value == null ? "" : value));
        }
        m.appendTail(out);
        return out.toString();
    }

    /** Sample values for the console live preview, covering the common placeholders. */
    public static Map<String, String> sampleVariables(final String realm) {
        final Map<String, String> sample = new LinkedHashMap<>();
        sample.put("realm", realm == null ? "your realm" : realm);
        sample.put("user", "Ada Lovelace");
        sample.put("code", "123456");
        sample.put("ttl", "5 minutes");
        sample.put("link", "https://helix.example/auth/magic?token=…");
        sample.put("number", "42");
        // User-claim passthrough (N6a): every claim of the signed-in user is available under user.<claim>.
        sample.put("user.email", "ada@example.com");
        sample.put("user.given_name", "Ada");
        sample.put("user.family_name", "Lovelace");
        sample.put("user.preferred_username", "ada");
        return sample;
    }
}
