/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A plain text per locale: {@code {"en": "Welcome", "nl": "Welkom", "default": "Welcome"}}. The key
 * {@value #DEFAULT} is the fallback for any locale. A bare JSON string is shorthand for {@code {"default": s}}.
 */
public record LocalizedText(Map<String, String> values) {

    /** The fallback key used when no entry matches the requested locale. */
    public static final String DEFAULT = "default";

    public LocalizedText {
        values = values == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(values));
    }

    /** A text for every locale. */
    public static LocalizedText of(final String text) {
        return new LocalizedText(Map.of(DEFAULT, text));
    }

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    static LocalizedText fromJson(final JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isTextual()) {
            return of(node.asText());
        }
        if (!node.isObject()) {
            throw new IllegalArgumentException("A localised text must be a string or an object of locale to text.");
        }
        final Map<String, String> out = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> {
            if (!e.getValue().isTextual()) {
                throw new IllegalArgumentException("A localised text value must be a string.");
            }
            out.put(e.getKey(), e.getValue().asText());
        });
        return new LocalizedText(out);
    }

    @JsonValue
    public Map<String, String> values() {
        return values;
    }

    /** The text for {@code locale}: exact tag, then its language, then {@value #DEFAULT}; null when none. */
    public String resolve(final Locale locale) {
        if (locale != null) {
            final String tag = locale.toLanguageTag();
            if (values.containsKey(tag)) {
                return values.get(tag);
            }
            if (values.containsKey(locale.getLanguage())) {
                return values.get(locale.getLanguage());
            }
        }
        return values.get(DEFAULT);
    }
}
