/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

/**
 * What {@link EmailOutbox#send} did with an email: the classified {@code result} of the first (synchronous) attempt,
 * and whether a failed attempt was queued for a retry.
 */
public record EmailSendOutcome(DeliveryResult result, boolean retryScheduled) {

    /** True when the provider took the email, or it is queued for a retry. */
    public boolean inFlight() {
        return result.isSuccess() || retryScheduled;
    }
}
