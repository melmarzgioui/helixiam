/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;

/**
 * Helix IAM notifications (N3): sends one SMS via a specific gateway. The registry picks the driver whose
 * {@link #driver()} matches the resolved provider's driver id ({@code TWILIO} / {@code HTTP}).
 */
public interface SmsDriver {

    /** The provider {@code driver} id this handles. */
    String driver();

    /** Send {@code message} to {@code to} using the resolved provider's config + secret. */
    void send(ResolvedProviderDto provider, String to, String message);
}
