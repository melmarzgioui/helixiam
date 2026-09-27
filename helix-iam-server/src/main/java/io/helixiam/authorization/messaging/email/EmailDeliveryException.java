/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

/**
 * An email that was not delivered, for callers of the boolean send API that report failure by exception. The
 * message is the result's safe diagnostic (never a secret or the body).
 */
public class EmailDeliveryException extends RuntimeException {

    private final transient DeliveryResult result;

    public EmailDeliveryException(final DeliveryResult result) {
        super("Email not delivered (" + result.status() + ", " + result.reason() + ")"
                + (result.diagnostic() == null ? "" : ": " + result.diagnostic()));
        this.result = result;
    }

    public DeliveryResult result() {
        return result;
    }
}
