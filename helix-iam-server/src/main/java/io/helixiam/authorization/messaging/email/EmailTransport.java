/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;

/**
 * The email transport SPI: one implementation per driver ({@code SMTP}, {@code CLOUDFLARE}, {@code HTTP},
 * {@code LOG}, …), registered as a Spring bean. {@link EmailDelivery} selects the transport whose {@link #driver()}
 * matches the provider configured for the realm (or the global default) and calls {@link #deliver}.
 *
 * <p>To add an API driver for another provider, implement this interface: read the non-secret settings from
 * {@code provider.config()} and the credential from {@code provider.secret()}, send {@code message} (both its HTML
 * and its text part), and classify the answer. Callers never depend on a concrete transport.
 *
 * <p>Contract:
 * <ul>
 *   <li>{@link #deliver} never throws for a delivery failure; it returns a {@link DeliveryResult} with the
 *       classified status. (An unexpected runtime exception is treated as a transient failure by the caller.)</li>
 *   <li>The diagnostic never contains the secret or the message body.</li>
 *   <li>It is safe to call again with the same message (same {@link EmailMessage#messageId()}) after a transient
 *       failure. A transport that supports idempotency keys should pass the message id.</li>
 * </ul>
 */
public interface EmailTransport {

    /** The driver id, matched case-insensitively against the provider's {@code driver}. */
    String driver();

    /** Deliver one message with the provider's settings and secret; returns the classified result. */
    DeliveryResult deliver(ResolvedProviderDto provider, EmailMessage message);
}
