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

    /**
     * Send one email. When {@code html} is true the {@code body} is delivered as {@code text/html}, with a plain-text
     * part derived from it ({@link io.helixiam.authorization.messaging.EmailText}).
     */
    void send(ResolvedProviderDto provider, String to, String subject, String body, boolean html);

    /**
     * Item 3: send one email with an explicit plain-text part. When {@code html} is true, {@code text} is the
     * {@code text/plain} alternative of the HTML {@code body} (null derives it from the HTML); for a plain email the
     * body is the text. The default ignores {@code text} (a driver that cannot send it).
     */
    default void send(final ResolvedProviderDto provider, final String to, final String subject, final String body,
                      final boolean html, final String text) {
        send(provider, to, subject, body, html);
    }
}
