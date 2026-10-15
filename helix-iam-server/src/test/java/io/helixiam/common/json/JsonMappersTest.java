/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.json;

import org.junit.jupiter.api.Test;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.exc.StreamConstraintsException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The Jackson 3 move keeps every read limit at least as strict as Jackson 2's, and HelixIAM's own code uses only
 * Jackson 3 ({@code jackson-annotations}, shared by both lines, excepted).
 */
class JsonMappersTest {

    /** Jackson 2.21's defaults: what the application's mappers applied before the move. */
    private static final int JACKSON2_MAX_STRING = 20_000_000;
    private static final int JACKSON2_MAX_DEPTH = 1000;
    private static final int JACKSON2_MAX_NUMBER = 1000;
    private static final int JACKSON2_MAX_NAME = 50_000;

    @Test
    void thePlainMapper_isAtLeastAsStrictAsJackson2() {
        assertAtLeastAsStrict(JsonMappers.plain());
        assertThat(JsonMappers.plain().tokenStreamFactory().streamReadConstraints().getMaxStringLength())
                .isEqualTo(JACKSON2_MAX_STRING);
        assertThat(JsonMappers.plain().tokenStreamFactory().streamReadConstraints().getMaxNestingDepth())
                .isEqualTo(500);
    }

    @Test
    void aFactoryWithOwnConstraints_keepsTheStringCapUnlessItOverridesIt() {
        final StreamReadConstraints depthOnly = JsonMappers.factoryBuilder(c -> c.maxNestingDepth(32)).build()
                .streamReadConstraints();
        assertThat(depthOnly.getMaxNestingDepth()).isEqualTo(32);
        assertThat(depthOnly.getMaxStringLength()).isEqualTo(JACKSON2_MAX_STRING);
        final StreamReadConstraints tighter = JsonMappers.factoryBuilder(c -> c.maxStringLength(1024 * 1024)).build()
                .streamReadConstraints();
        assertThat(tighter.getMaxStringLength()).isEqualTo(1024 * 1024);
        assertThat(tighter.getMaxNestingDepth()).isEqualTo(500);
    }

    @Test
    void tooDeepADocument_isRefused() {
        final int depth = JsonMappers.plain().tokenStreamFactory().streamReadConstraints().getMaxNestingDepth() + 1;
        final String doc = "[".repeat(depth) + "]".repeat(depth);
        assertThatThrownBy(() -> JsonMappers.plain().readTree(doc)).isInstanceOf(StreamConstraintsException.class);
    }

    @Test
    void theStricterMappers_keepTheirOwnLimits() {
        final StreamReadConstraints strict = io.helixiam.authorization.federation.wallet.StrictJson.MAPPER
                .tokenStreamFactory().streamReadConstraints();
        assertThat(strict.getMaxNestingDepth()).isEqualTo(64);
        assertThat(io.helixiam.authorization.federation.wallet.StrictJson.MAPPER.tokenStreamFactory()
                .streamReadConstraints().getMaxNestingDepth()).isEqualTo(64);
        assertThat(strict.getMaxStringLength()).isEqualTo(JACKSON2_MAX_STRING);
        assertThatThrownBy(() -> io.helixiam.authorization.federation.wallet.StrictJson.MAPPER
                .readTree("[".repeat(65) + "]".repeat(65))).isInstanceOf(StreamConstraintsException.class);
        assertThatThrownBy(() -> io.helixiam.authorization.federation.wallet.StrictJson.MAPPER
                .readTree("{\"a\":1,\"a\":2}")).isInstanceOf(tools.jackson.core.JacksonException.class);
        assertThatThrownBy(() -> io.helixiam.authorization.federation.wallet.StrictJson.MAPPER
                .readTree("{\"a\":1} x")).isInstanceOf(tools.jackson.core.JacksonException.class);
    }

    static void assertAtLeastAsStrict(final ObjectMapper mapper) {
        final StreamReadConstraints c = mapper.tokenStreamFactory().streamReadConstraints();
        assertThat(c.getMaxStringLength()).isPositive().isLessThanOrEqualTo(JACKSON2_MAX_STRING);
        assertThat(c.getMaxNestingDepth()).isPositive().isLessThanOrEqualTo(JACKSON2_MAX_DEPTH);
        assertThat(c.getMaxNumberLength()).isPositive().isLessThanOrEqualTo(JACKSON2_MAX_NUMBER);
        assertThat(c.getMaxNameLength()).isPositive().isLessThanOrEqualTo(JACKSON2_MAX_NAME);
    }

    @Test
    void theApplicationCode_usesOnlyJackson3() throws IOException {
        // jackson-annotations (com.fasterxml.jackson.annotation) is shared by Jackson 2 and 3; nothing else of Jackson 2.
        final Pattern jackson2 = Pattern.compile("com\\.fasterxml\\.jackson\\.(core|databind|dataformat|datatype|module)");
        final List<Path> offenders;
        try (Stream<Path> files = Files.walk(Path.of("src", "main", "java"))) {
            offenders = files.filter(p -> p.toString().endsWith(".java")).filter(p -> {
                try {
                    return jackson2.matcher(Files.readString(p)).find();
                } catch (final IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
            }).toList();
        }
        assertThat(offenders).isEmpty();
    }
}
