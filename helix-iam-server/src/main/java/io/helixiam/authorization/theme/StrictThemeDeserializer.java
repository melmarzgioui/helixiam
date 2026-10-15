/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;

/**
 * Deserialises a {@link Theme} strictly (unknown fields fail) wherever it is embedded in a request document, such as
 * the realm import document. The mapping error keeps its JSON path, so {@code AdminValidationAdvice} answers
 * {@code 400} with {@code fieldErrors} keyed like {@code theme.colors.primry}.
 */
public class StrictThemeDeserializer extends ValueDeserializer<Theme> {

    @Override
    public Theme deserialize(final JsonParser p, final DeserializationContext ctxt) {
        final JsonNode node = ctxt.readTree(p);
        return ThemeJson.strictMapper().treeToValue(node, Theme.class);
    }
}
