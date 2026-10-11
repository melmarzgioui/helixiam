/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

/**
 * An {@link SsrfBlockedException} raised because the outbound host could not be resolved (unknown host, or no
 * address), not because the URL is refused by policy. Callers that distinguish a transient availability failure from
 * a policy refusal (the wallet status-list client) catch this subtype; everyone else keeps treating it as a refusal.
 */
public class UnresolvableHostException extends SsrfBlockedException {

    public UnresolvableHostException(final String message) {
        super(message);
    }

    public UnresolvableHostException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
