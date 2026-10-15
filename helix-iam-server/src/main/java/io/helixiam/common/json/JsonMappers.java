/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.json;

import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.ToStringSerializer;

import java.util.Locale;

/**
 * The application's own Jackson 3 mappers (everything outside Spring MVC, whose mapper Spring Boot configures, see
 * {@code application.properties}).
 *
 * <p>HelixIAM moved from Jackson 2 to Jackson 3 after 1.0. What the stores hold and what clients receive was written
 * by Jackson 2's defaults, and Jackson 3 changed many of them (properties sorted alphabetically, enums written with
 * {@code toString()}, {@code null} for a primitive and trailing tokens refused, dates as ISO strings, characters
 * outside the BMP written raw in UTF-8, …). {@link #plain()} therefore behaves exactly like a default Jackson 2
 * {@code new ObjectMapper()} did: Jackson 3's own Jackson 2 compatibility defaults for the mapper and the factory,
 * {@link #jackson2Compatible what those defaults leave out}, and Jackson 2's maximum string length (Jackson 3 allows
 * five times more). Jackson 3's maximum nesting depth (500,
 * Jackson 2: 1000) is kept: stricter, and deeper than anything HelixIAM stores or accepts. The upgrade fixtures under
 * {@code src/test/resources/upgrade/jackson2} hold the evidence.
 *
 * <p>Jackson 3 mappers are immutable, so one instance is shared.
 */
public final class JsonMappers {

    /** Jackson 2's {@code StreamReadConstraints.DEFAULT_MAX_STRING_LEN}. */
    public static final int MAX_STRING_LENGTH = 20_000_000;

    private static final JsonMapper PLAIN = plainBuilder().build();

    private JsonMappers() {
    }

    /** A default Jackson 2 {@code ObjectMapper}'s behaviour on Jackson 3 (see the class comment). */
    public static JsonMapper plain() {
        return PLAIN;
    }

    /** {@link #plain()}'s configuration, to adjust (e.g. a strict reader). */
    public static JsonMapper.Builder plainBuilder() {
        return jackson2Compatible(JsonMapper.builder(factoryBuilder().build()).configureForJackson2());
    }

    /**
     * What Jackson 3's {@code configureForJackson2()} does not restore: Jackson 2's JavaBean property names
     * ({@code getURL()} is {@code url}, see {@link Jackson2AccessorNaming}) and a {@link Locale} written as
     * {@code toString()} ({@code nl_NL}; Jackson 3 writes the language tag {@code nl-NL}). Applied to every mapper of
     * the application, Spring MVC's included ({@code JacksonConfig}).
     */
    public static <M extends tools.jackson.databind.ObjectMapper, B extends MapperBuilder<M, B>> B jackson2Compatible(
            final B builder) {
        return builder.accessorNaming(new Jackson2AccessorNaming())
                .addModule(new SimpleModule("helix-jackson2-compatibility")
                        .addSerializer(Locale.class, new ToStringSerializer(Locale.class)));
    }

    /**
     * A JSON factory with Jackson 2's defaults and {@link #MAX_STRING_LENGTH}, for mappers that set their own read
     * constraints (the caller's {@code streamReadConstraints} replaces these, so it must keep the string limit).
     */
    public static JsonFactoryBuilder factoryBuilder() {
        return JsonFactory.builderWithJackson2Defaults().streamReadConstraints(readConstraints().build());
    }

    /** Jackson 3's read constraints with Jackson 2's maximum string length. */
    public static StreamReadConstraints.Builder readConstraints() {
        return StreamReadConstraints.builder().maxStringLength(MAX_STRING_LENGTH);
    }
}
