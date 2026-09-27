/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A list of plain texts per locale (brand badges). A bare JSON array is shorthand for {@code {"default": [...]}};
 * an empty list is an explicit "none".
 */
public record LocalizedList(Map<String, List<String>> values) {

    public LocalizedList {
        final Map<String, List<String>> copy = new LinkedHashMap<>();
        if (values != null) {
            values.forEach((k, v) -> copy.put(k, v == null ? List.of() : List.copyOf(v)));
        }
        values = Collections.unmodifiableMap(copy);
    }

    /** The same list for every locale. */
    public static LocalizedList of(final List<String> items) {
        return new LocalizedList(Map.of(LocalizedText.DEFAULT, items));
    }

    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    static LocalizedList fromJson(final JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isArray()) {
            return of(strings(node));
        }
        if (!node.isObject()) {
            throw new IllegalArgumentException("A localised list must be an array or an object of locale to array.");
        }
        final Map<String, List<String>> out = new LinkedHashMap<>();
        node.fields().forEachRemaining(e -> out.put(e.getKey(), strings(e.getValue())));
        return new LocalizedList(out);
    }

    private static List<String> strings(final JsonNode array) {
        if (!array.isArray()) {
            throw new IllegalArgumentException("A localised list value must be an array of strings.");
        }
        final List<String> out = new ArrayList<>();
        array.forEach(n -> {
            if (!n.isTextual()) {
                throw new IllegalArgumentException("A localised list item must be a string.");
            }
            out.add(n.asText());
        });
        return out;
    }

    @JsonValue
    public Map<String, List<String>> values() {
        return values;
    }

    /** The list for {@code locale}: exact tag, then language, then the default; null when none. */
    public List<String> resolve(final Locale locale) {
        if (locale != null) {
            final String tag = locale.toLanguageTag();
            if (values.containsKey(tag)) {
                return values.get(tag);
            }
            if (values.containsKey(locale.getLanguage())) {
                return values.get(locale.getLanguage());
            }
        }
        return values.get(LocalizedText.DEFAULT);
    }
}
