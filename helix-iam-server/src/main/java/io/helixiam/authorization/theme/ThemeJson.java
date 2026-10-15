/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import io.helixiam.common.json.JsonMappers;
import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;

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

    private static final ObjectMapper MAPPER = JsonMappers.plainBuilder()
            .changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(JsonInclude.Include.NON_NULL))
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            // Jackson 3 keeps creator (record component) properties first, in declaration order; Jackson 2 sorted
            // them too (SORT_CREATOR_PROPERTIES_BY_DECLARATION_ORDER=false). The canonical form, and so the stored
            // rows and the version hash, stay sorted as 1.0 wrote them (ThemeJsonUpgradeTest).
            .configure(MapperFeature.SORT_CREATOR_PROPERTIES_FIRST, false)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    /** Admin-API input: unknown fields are errors (a typo must never silently clear a field under PUT-replace). */
    private static final ObjectMapper STRICT = JsonMappers.plainBuilder()
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
        } catch (final tools.jackson.databind.DatabindException e) {
            throw new ThemeValidationException(java.util.Map.of(path(e),
                    e instanceof tools.jackson.databind.exc.UnrecognizedPropertyException
                            ? "Unknown field." : "Invalid value."));
        } catch (final JacksonException | IllegalArgumentException e) {
            throw new ThemeValidationException(java.util.Map.of("theme", "Invalid value."));
        }
    }

    /** The strict mapper, for {@link StrictThemeDeserializer}. */
    static ObjectMapper strictMapper() {
        return STRICT;
    }

    /** {@code a.b[0].c} from a mapping exception's reference path. */
    public static String path(final tools.jackson.databind.DatabindException e) {
        final StringBuilder out = new StringBuilder();
        for (final tools.jackson.core.JacksonException.Reference ref : e.getPath()) {
            if (ref.getPropertyName() != null) {
                out.append(out.isEmpty() ? "" : ".").append(ref.getPropertyName());
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
        } catch (final JacksonException e) {
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
        } catch (final JacksonException e) {
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
