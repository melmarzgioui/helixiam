/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

/**
 * Thrown by {@link OutboundUrlGuard} when a requested outbound URL is rejected because its scheme is not
 * {@code http}/{@code https}, it cannot be resolved, or it resolves to a loopback / link-local (incl. the
 * {@code 169.254.169.254} cloud-metadata address) / private / multicast / wildcard address. Unchecked so it
 * flows through the callers' existing best-effort {@code catch (Exception)} handling without new checked
 * signatures — see M6 (SSRF) in {@code SECURITY-REVIEW.md}.
 */
public class SsrfBlockedException extends RuntimeException {

    public SsrfBlockedException(final String message) {
        super(message);
    }

    public SsrfBlockedException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
