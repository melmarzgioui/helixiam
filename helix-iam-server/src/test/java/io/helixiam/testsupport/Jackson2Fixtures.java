/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JSON written by HelixIAM on Jackson 2 (the 1.0 line up to {@code v1.0.0-rc.10}), kept under
 * {@code src/test/resources/upgrade/jackson2}: what the stores hold at the upgrade and what clients and webhook
 * receivers were sent. The tests that use them compile on both lines and check two things: the current code still
 * reads every fixture, and it still writes the same bytes.
 *
 * <p>The fixtures were recorded once on the Jackson 2 code with {@code -Dhelix.upgrade.record=true}, which writes the
 * current output instead of comparing it. Never record them again on a later line: they are the evidence.
 */
public final class Jackson2Fixtures {

    private static final String RESOURCE_DIR = "/upgrade/jackson2/";
    private static final Path SOURCE_DIR = Path.of("src", "test", "resources", "upgrade", "jackson2");

    private Jackson2Fixtures() {
    }

    /** Whether this run records the fixtures instead of comparing against them. */
    public static boolean recording() {
        return Boolean.getBoolean("helix.upgrade.record");
    }

    /** The fixture {@code name} as written by the Jackson 2 line (UTF-8, exactly as stored or sent). */
    public static String read(final String name) {
        if (recording()) {
            try {
                return Files.readString(SOURCE_DIR.resolve(name), StandardCharsets.UTF_8);
            } catch (final IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        try (InputStream in = Jackson2Fixtures.class.getResourceAsStream(RESOURCE_DIR + name)) {
            if (in == null) {
                throw new IllegalStateException("missing Jackson 2 fixture " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * {@code actual} is byte for byte what the Jackson 2 line wrote for {@code name}. In recording mode the fixture
     * is (re)written instead.
     */
    public static void assertWritesSame(final String name, final String actual) {
        if (recording()) {
            try {
                Files.createDirectories(SOURCE_DIR);
                Files.writeString(SOURCE_DIR.resolve(name), actual, StandardCharsets.UTF_8);
            } catch (final IOException e) {
                throw new UncheckedIOException(e);
            }
            return;
        }
        assertThat(actual).as("output differs from what the Jackson 2 line wrote (%s)", name).isEqualTo(read(name));
    }
}
