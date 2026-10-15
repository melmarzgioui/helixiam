/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.json;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link JsonNodes} answers exactly what Jackson 2.21's {@code asText()}, {@code asText("D")} and
 * {@code asBoolean(true/false)} answered for every kind of node (the table was printed by Jackson 2.21.7).
 */
class JsonNodesTest {

    private static final String DOC = "{\"t\":true,\"f\":false,\"i0\":0,\"i\":12,\"neg\":-1,\"l\":12345678901,"
            + "\"d\":1.5,\"d0\":0.0,\"st\":\"true\",\"sts\":\" true \",\"sf\":\"false\",\"sT\":\"TRUE\",\"s1\":\"1\","
            + "\"s\":\"abc\",\"e\":\"\",\"n\":null,\"o\":{},\"a\":[1],\"big\":123456789012345678901234567890}";

    /** key, asBoolean(true), asBoolean(false), asText(), asText("D") on Jackson 2. */
    private static final String[][] JACKSON2 = {
            {"t", "true", "true", "true", "true"},
            {"f", "false", "false", "false", "false"},
            {"i0", "false", "false", "0", "0"},
            {"i", "true", "true", "12", "12"},
            {"neg", "true", "true", "-1", "-1"},
            {"l", "true", "true", "12345678901", "12345678901"},
            {"d", "true", "false", "1.5", "1.5"},
            {"d0", "true", "false", "0.0", "0.0"},
            {"st", "true", "true", "true", "true"},
            {"sts", "true", "true", " true ", " true "},
            {"sf", "false", "false", "false", "false"},
            {"sT", "true", "false", "TRUE", "TRUE"},
            {"s1", "true", "false", "1", "1"},
            {"s", "true", "false", "abc", "abc"},
            {"e", "true", "false", "", ""},
            {"n", "true", "false", "null", "D"},
            {"o", "true", "false", "", ""},
            {"a", "true", "false", "", ""},
            {"big", "true", "true", "123456789012345678901234567890", "123456789012345678901234567890"},
            {"MISSING", "true", "false", "", "D"},
    };

    @Test
    void answersAsJackson2Did() {
        final JsonNode root = JsonMappers.plain().readTree(DOC);
        for (final String[] row : JACKSON2) {
            final JsonNode n = root.path(row[0]);
            assertThat(JsonNodes.bool(n, true)).as(row[0] + " asBoolean(true)").isEqualTo(Boolean.parseBoolean(row[1]));
            assertThat(JsonNodes.bool(n, false)).as(row[0] + " asBoolean(false)").isEqualTo(Boolean.parseBoolean(row[2]));
            assertThat(JsonNodes.text(n)).as(row[0] + " asText()").isEqualTo(row[3]);
            assertThat(JsonNodes.text(n, "D")).as(row[0] + " asText(D)").isEqualTo(row[4]);
        }
    }
}
