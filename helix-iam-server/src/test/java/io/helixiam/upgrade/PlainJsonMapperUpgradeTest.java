/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.upgrade;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static io.helixiam.testsupport.Jackson2Fixtures.assertWritesSame;
import static io.helixiam.testsupport.Jackson2Fixtures.read;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jackson 3 upgrade: the stores that keep a flat settings map or a string list as JSON
 * ({@code identity_provider.config_json} and {@code secret_json}, {@code auth_flow_execution.config},
 * {@code messaging_provider.config}, the trusted-list settings, …) wrote it with a default Jackson 2 mapper. This pins
 * what that mapper wrote and how it read such text, so the mapper those stores use after the upgrade can be checked
 * against it byte for byte and value for value.
 */
class PlainJsonMapperUpgradeTest {

    private static final TypeReference<LinkedHashMap<String, String>> STRING_MAP = new TypeReference<>() { };
    private static final TypeReference<List<String>> STRINGS = new TypeReference<>() { };

    /** The mapper the stores use. */
    private static ObjectMapper mapper() {
        return new ObjectMapper();
    }

    private static Map<String, String> settings() {
        final Map<String, String> m = new LinkedHashMap<>();
        m.put("issuer", "https://login.example.eu/realms/a/");
        m.put("scopes", "[\"openid\",\"email\"]");
        m.put("displayName", "Zoë's <IdP> & \"Co\"");
        m.put("control", "tab\t nl\n cr\r nul\u0000 bell\u0007 del\u007f");
        m.put("separators", "\u2028\u2029");
        m.put("emoji", "\uD83D\uDE00");
        m.put("backslash", "C:\\path\\");
        m.put("empty", "");
        m.put("nothing", null);
        m.put("zeta", "last");
        m.put("alpha", "after zeta");
        return m;
    }

    @Test
    void aSettingsMap_isWrittenAndReadAsBefore() throws Exception {
        assertWritesSame("plain-settings-map.json", mapper().writeValueAsString(settings()));

        assertThat(mapper().readValue(read("plain-settings-map.json"), STRING_MAP)).containsExactlyEntriesOf(settings());
    }

    @Test
    void aStringList_isWrittenAndReadAsBefore() throws Exception {
        final List<String> values = List.of("dc+sd-jwt", "https://a.example/x?y=1&z=2", "Zoë", "\u2028", "");
        assertWritesSame("plain-string-list.json", mapper().writeValueAsString(values));

        assertThat(mapper().readValue(read("plain-string-list.json"), STRINGS)).isEqualTo(values);
    }

    @Test
    void storedTextIsReadWithTheSameLeniency() {
        // Values a hand-edited or older row might hold, and how a default Jackson 2 mapper read them.
        final StringBuilder out = new StringBuilder();
        probe(out, "scalars-as-strings", () -> mapper().readValue(
                "{\"n\":1,\"b\":true,\"f\":1.50,\"big\":123456789012345678901234567890,\"z\":null}", STRING_MAP));
        probe(out, "duplicate-key", () -> mapper().readValue("{\"a\":\"1\",\"a\":\"2\"}", STRING_MAP));
        probe(out, "trailing-tokens", () -> mapper().readValue("{\"a\":\"1\"} {\"b\":2}", STRING_MAP));
        probe(out, "trailing-garbage-tree", () -> mapper().readTree("[\"a\"] x"));
        probe(out, "object-value", () -> mapper().readValue("{\"a\":{\"b\":1}}", STRING_MAP));
        probe(out, "array-value", () -> mapper().readValue("{\"a\":[1]}", STRING_MAP));
        probe(out, "not-json", () -> mapper().readValue("not json", STRING_MAP));
        probe(out, "empty-text-tree", () -> describe(mapper().readTree("")));
        probe(out, "blank-text-tree", () -> describe(mapper().readTree("  ")));
        probe(out, "null-literal-tree", () -> describe(mapper().readTree("null")));
        probe(out, "null-literal-map", () -> mapper().readValue("null", STRING_MAP));
        probe(out, "list-from-scalar", () -> mapper().readValue("\"a\"", STRINGS));
        probe(out, "list-with-number", () -> mapper().readValue("[\"a\",1,true,null]", STRINGS));
        probe(out, "single-quotes", () -> mapper().readValue("{'a':'1'}", STRING_MAP));
        probe(out, "comments", () -> mapper().readValue("{/*c*/\"a\":\"1\"}", STRING_MAP));
        probe(out, "nan", () -> mapper().readTree("[NaN]"));
        probe(out, "leading-zero", () -> mapper().readTree("[01]"));
        probe(out, "control-in-string", () -> mapper().readTree("[\"a\u0001b\"]"));
        probe(out, "tree-numbers", () -> mapper().writeValueAsString(
                mapper().readTree("{\"i\":1,\"l\":12345678901,\"d\":1.10,\"e\":1e2,\"m\":-0.0,\"bi\":123456789012345678901234567890}")));
        assertWritesSame("plain-read-leniency.txt", out.toString());
    }

    private static String describe(final JsonNode node) {
        return node == null ? "java-null" : node.getNodeType() + ":" + node;
    }

    private static void probe(final StringBuilder out, final String name, final Callable<Object> c) {
        String result;
        try {
            final Object v = c.call();
            result = "ok " + v;
        } catch (final Exception e) {
            result = "refused";
        }
        out.append(name).append(" -> ").append(result).append('\n');
    }
}
