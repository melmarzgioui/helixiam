/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

/** Fetches one published list (a trusted list, a list of trusted lists or a LoTE) as raw bytes. */
@FunctionalInterface
public interface TrustedListFetcher {

    /**
     * The body of {@code url}, fetched for {@code realm} (the fetch limiter's partition).
     *
     * @throws TrustedListException {@code POLICY} when the URL is refused, {@code REDIRECT}, {@code TOO_LARGE} or
     *                              {@code FETCH} otherwise
     */
    byte[] fetch(String url, String realm) throws TrustedListException;
}
