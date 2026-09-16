/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators.otp;

import java.util.function.LongSupplier;

/** Helix IAM E3.1: one-time code delivered by email. */
public class EmailOtpAuthenticator extends OtpDeliveryAuthenticator {

    public EmailOtpAuthenticator(final OtpSender sender, final LongSupplier clock) {
        super(sender, clock);
    }

    @Override
    protected String id() {
        return "email-otp";
    }

    @Override
    protected String displayName() {
        return "One-Time Code (Email)";
    }
}
