/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * The canonical JSON form of a {@link Theme}: how it is stored ({@code realm_theme.theme_json},
 * {@code organization_theme.theme_json}), exported, and hashed. Independent of Spring so the Flyway data migration
 * can use it. Null fields are omitted and properties are sorted, so equal themes serialise identically.
 */
public final class ThemeJson {

    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    /** Admin-API input: unknown fields are errors (a typo must never silently clear a field under PUT-replace). */
    private static final ObjectMapper STRICT = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
            .build();

    private ThemeJson() {
    }

    /**
     * Parses admin-API or import input strictly. Unknown fields and values of the wrong type are reported as
     * {@link ThemeValidationException} keyed by their JSON path ({@code colors.primry}: "Unknown field.").
     */
    public static Theme readStrict(final JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return Theme.EMPTY;
        }
        if (!node.isObject()) {
            throw new ThemeValidationException(java.util.Map.of("theme", "A theme must be a JSON object."));
        }
        try {
            final Theme t = STRICT.treeToValue(node, Theme.class);
            return t == null ? Theme.EMPTY : t;
        } catch (final com.fasterxml.jackson.databind.JsonMappingException e) {
            throw new ThemeValidationException(java.util.Map.of(path(e),
                    e instanceof com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException
                            ? "Unknown field." : "Invalid value."));
        } catch (final JsonProcessingException | IllegalArgumentException e) {
            throw new ThemeValidationException(java.util.Map.of("theme", "Invalid value."));
        }
    }

    /** The strict mapper, for {@link StrictThemeDeserializer}. */
    static ObjectMapper strictMapper() {
        return STRICT;
    }

    /** {@code a.b[0].c} from a mapping exception's reference path. */
    public static String path(final com.fasterxml.jackson.databind.JsonMappingException e) {
        final StringBuilder out = new StringBuilder();
        for (final com.fasterxml.jackson.databind.JsonMappingException.Reference ref : e.getPath()) {
            if (ref.getFieldName() != null) {
                out.append(out.isEmpty() ? "" : ".").append(ref.getFieldName());
            } else if (ref.getIndex() >= 0) {
                out.append('[').append(ref.getIndex()).append(']');
            }
        }
        return out.isEmpty() ? "theme" : out.toString();
    }

    /** Canonical JSON for a theme ({@code {}} for null). */
    public static String write(final Theme theme) {
        try {
            return MAPPER.writeValueAsString(theme == null ? Theme.EMPTY : theme);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("Theme could not be serialised", e);
        }
    }

    /** Parses stored JSON; blank or null is {@link Theme#EMPTY}. */
    public static Theme read(final String json) {
        if (json == null || json.isBlank()) {
            return Theme.EMPTY;
        }
        try {
            final Theme t = MAPPER.readValue(json, Theme.class);
            return t == null ? Theme.EMPTY : t;
        } catch (final JsonProcessingException e) {
            throw new IllegalArgumentException("Stored theme is not valid JSON: " + e.getOriginalMessage(), e);
        }
    }

    /** The theme as a JSON tree (for field-level diffs). */
    public static JsonNode tree(final Theme theme) {
        return MAPPER.valueToTree(theme == null ? Theme.EMPTY : theme);
    }

    /** SHA-256 (hex) of the canonical JSON — a stable version for ETags. */
    public static String hash(final Theme theme) {
        try {
            final byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(write(theme).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
