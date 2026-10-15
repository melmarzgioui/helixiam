/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.common.json.JsonMappers;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * The one strict JSON configuration every JOSE/SD-JWT/JWE payload in this package decodes with: duplicate member
 * names refused ({@link StreamReadFeature#STRICT_DUPLICATE_DETECTION}), integers as {@link Long} (like Nimbus),
 * nothing trailing after the value, nesting bounded. Untrusted wallet input is never parsed with a plain
 * {@link ObjectMapper}.
 */
public final class StrictJson {

    /** Deep enough for any real payload, shallow enough that a crafted document cannot exhaust the stack. */
    private static final int MAX_NESTING_DEPTH = 64;

    public static final ObjectMapper MAPPER = JsonMappers.jackson2Compatible(JsonMapper.builder(
                    JsonMappers.factoryBuilder()
                            .streamReadConstraints(JsonMappers.readConstraints().maxNestingDepth(MAX_NESTING_DEPTH)
                                    .build())
                            .build())
                    .configureForJackson2())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.USE_LONG_FOR_INTS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private StrictJson() { }
}
