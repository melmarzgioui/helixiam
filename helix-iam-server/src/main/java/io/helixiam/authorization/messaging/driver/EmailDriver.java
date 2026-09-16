/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;

/**
 * Helix IAM notifications (N3): sends one email via a specific transport ({@code SMTP} / {@code HTTP}). The
 * registry picks the driver whose {@link #driver()} matches the resolved provider's driver id.
 */
public interface EmailDriver {

    String driver();

    /** Send one email. When {@code html} is true the {@code body} is delivered as {@code text/html}. */
    void send(ResolvedProviderDto provider, String to, String subject, String body, boolean html);
}
