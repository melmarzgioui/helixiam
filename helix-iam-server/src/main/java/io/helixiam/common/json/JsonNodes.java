/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.json;

import tools.jackson.databind.JsonNode;

/**
 * Jackson 2's lenient {@link JsonNode} accessors, for JSON HelixIAM does not control (imports, provider responses,
 * stored rows, client input) read by code written against Jackson 2.
 *
 * <p>Jackson 3's {@code asString()} throws for an object or an array (Jackson 2's {@code asText()} gave {@code ""})
 * and gives {@code ""} for {@code null} (Jackson 2: {@code "null"}); its {@code asBoolean()} throws for a string that
 * is not a boolean (Jackson 2: the default). Where such input must keep failing softly (a value read as empty, a
 * default), the code uses these instead, so a malformed document is still refused or ignored the way it was rather
 * than surfacing as an unexpected exception. Code that checks the node type first ({@code isString()}) uses Jackson 3's
 * accessors directly.
 */
public final class JsonNodes {

    private JsonNodes() {
    }

    /** Jackson 2's {@code asText()}: a string's value, a scalar's text, {@code "null"}, {@code ""} for a container. */
    public static String text(final JsonNode node) {
        if (node.isString()) {
            return node.stringValue();
        }
        if (node.isNull()) {
            return "null";
        }
        if (node.isContainer() || node.isMissingNode()) {
            return "";
        }
        return node.asString();
    }

    /** Jackson 2's {@code asText(def)}: {@code def} for {@code null} or a missing node, otherwise {@link #text}. */
    public static String text(final JsonNode node, final String def) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return def;
        }
        return text(node);
    }

    /**
     * Jackson 2's {@code asBoolean(def)}: a boolean's value, an integer's {@code != 0}, the strings {@code "true"} /
     * {@code "false"} (trimmed), otherwise {@code def}.
     */
    public static boolean bool(final JsonNode node, final boolean def) {
        if (node == null) {
            return def;
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isIntegralNumber()) {
            return node.bigIntegerValue().signum() != 0;
        }
        if (node.isString()) {
            final String v = node.stringValue().trim();
            if ("true".equals(v)) {
                return true;
            }
            if ("false".equals(v)) {
                return false;
            }
        }
        return def;
    }
}
