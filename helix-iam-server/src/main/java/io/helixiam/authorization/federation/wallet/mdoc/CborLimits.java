/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

/**
 * Bounds for one {@link StrictCbor#decode} call.
 *
 * @param maxDepth maximum container nesting (a bare scalar has depth 0, {@code [0]} has depth 1)
 * @param maxItems maximum data items, counting every container, every map key and every value
 * @param maxBytes maximum encoded input size
 */
public record CborLimits(int maxDepth, int maxItems, int maxBytes) {

    /** The plan defaults: depth ≤ 16, items ≤ 10 000, bytes ≤ 256 KiB. */
    public static final CborLimits DEFAULTS = new CborLimits(16, 10_000, 256 * 1024);

    public CborLimits {
        if (maxDepth < 1 || maxItems < 1 || maxBytes < 1) {
            throw new IllegalArgumentException("CBOR limits must be positive");
        }
    }
}
