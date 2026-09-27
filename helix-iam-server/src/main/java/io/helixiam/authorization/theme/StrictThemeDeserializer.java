/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;

/**
 * Deserialises a {@link Theme} strictly (unknown fields fail) wherever it is embedded in a request document, such as
 * the realm import document. The mapping error keeps its JSON path, so {@code AdminValidationAdvice} answers
 * {@code 400} with {@code fieldErrors} keyed like {@code theme.colors.primry}.
 */
public class StrictThemeDeserializer extends JsonDeserializer<Theme> {

    @Override
    public Theme deserialize(final JsonParser p, final DeserializationContext ctxt) throws IOException {
        final JsonNode node = p.readValueAsTree();
        return ThemeJson.strictMapper().treeToValue(node, Theme.class);
    }
}
