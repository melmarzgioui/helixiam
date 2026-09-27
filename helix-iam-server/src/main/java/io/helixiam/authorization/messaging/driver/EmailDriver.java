/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailTransport;

/**
 * The previous email-driver contract, kept so an existing custom driver still works: implement
 * {@link #send(ResolvedProviderDto, String, String, String, boolean)} (throwing on failure), and {@link #deliver}
 * adapts it to the {@link EmailTransport} SPI (a thrown exception is a transient failure).
 *
 * @deprecated implement {@link EmailTransport} instead: it carries the whole message (reply-to, several recipients,
 *             the stable message id) and returns a classified {@link DeliveryResult}.
 */
@Deprecated(since = "1.0")
public interface EmailDriver extends EmailTransport {

    /**
     * Send one email. When {@code html} is true the {@code body} is delivered as {@code text/html}, with a plain-text
     * part derived from it ({@link io.helixiam.authorization.messaging.EmailText}).
     */
    void send(ResolvedProviderDto provider, String to, String subject, String body, boolean html);

    /**
     * Send one email with an explicit plain-text part ({@code text}; null derives it from the HTML). The default
     * ignores {@code text} (a driver that cannot send it).
     */
    default void send(final ResolvedProviderDto provider, final String to, final String subject, final String body,
                      final boolean html, final String text) {
        send(provider, to, subject, body, html);
    }

    @Override
    default DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage message) {
        try {
            send(provider, message.primaryRecipient().address(), message.subject(),
                    message.isHtml() ? message.html() : message.text(), message.isHtml(), message.text());
            return DeliveryResult.accepted(null, null);
        } catch (final RuntimeException e) {
            return DeliveryResult.transientFailure(DeliveryResult.Reason.PROVIDER_ERROR,
                    "Email driver " + driver() + " failed (" + e.getClass().getSimpleName() + ")");
        }
    }
}
