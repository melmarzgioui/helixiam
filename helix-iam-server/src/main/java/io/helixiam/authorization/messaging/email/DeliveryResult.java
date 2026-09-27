/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import java.util.List;

/**
 * The classified outcome of one delivery attempt.
 *
 * <ul>
 *   <li>{@code status}: {@link Status#ACCEPTED} (the provider took it, or delivered it), {@link Status#QUEUED} (the
 *       provider accepted it but will deliver later), {@link Status#PERMANENT_FAILURE} (retrying the same email will
 *       not help) or {@link Status#TRANSIENT_FAILURE} (a retry may succeed, including failures the operator must fix,
 *       such as a revoked API token);</li>
 *   <li>{@code reason}: why, in a fixed vocabulary ({@link Reason});</li>
 *   <li>{@code providerMessageId}: the provider's id for the message, when it returns one;</li>
 *   <li>{@code diagnostic}: a short, safe explanation for logs, metrics and the admin test endpoint. It never contains
 *       a secret or the message body;</li>
 *   <li>{@code bouncedRecipients}: the addresses the provider reported as permanently bounced (empty otherwise).</li>
 * </ul>
 */
public record DeliveryResult(Status status, Reason reason, String providerMessageId, String diagnostic,
                             List<String> bouncedRecipients) {

    /** The delivery status. */
    public enum Status {
        ACCEPTED, QUEUED, PERMANENT_FAILURE, TRANSIENT_FAILURE
    }

    /** Why an attempt ended as it did. */
    public enum Reason {
        /** Accepted or queued. */
        NONE,
        /** The recipient's address bounced permanently. */
        RECIPIENT_BOUNCED,
        /** The provider refused this message (malformed, too large, policy). */
        MESSAGE_REJECTED,
        /** The provider refused the credentials (bad token or password, sending domain not allowed). */
        AUTHENTICATION,
        /** The provider asked us to slow down. */
        RATE_LIMITED,
        /** The provider failed (5xx, 4xx SMTP reply, unexpected answer). */
        PROVIDER_ERROR,
        /** Connection, timeout or TLS failure. */
        NETWORK,
        /** The provider settings are unusable (missing host, disallowed URL or TLS mode, unknown driver). */
        CONFIGURATION,
        /** No email provider is configured for the realm, nor globally. */
        NO_PROVIDER
    }

    private static final int MAX_DIAGNOSTIC = 300;

    public DeliveryResult {
        if (status == null) {
            throw new IllegalArgumentException("status is required");
        }
        reason = reason == null ? Reason.NONE : reason;
        diagnostic = clean(diagnostic);
        bouncedRecipients = bouncedRecipients == null ? List.of() : List.copyOf(bouncedRecipients);
    }

    public static DeliveryResult accepted(final String providerMessageId, final String diagnostic) {
        return new DeliveryResult(Status.ACCEPTED, Reason.NONE, providerMessageId, diagnostic, List.of());
    }

    public static DeliveryResult queued(final String providerMessageId, final String diagnostic) {
        return new DeliveryResult(Status.QUEUED, Reason.NONE, providerMessageId, diagnostic, List.of());
    }

    public static DeliveryResult permanent(final Reason reason, final String diagnostic) {
        return new DeliveryResult(Status.PERMANENT_FAILURE, reason, null, diagnostic, List.of());
    }

    public static DeliveryResult bounced(final List<String> recipients, final String diagnostic) {
        return new DeliveryResult(Status.PERMANENT_FAILURE, Reason.RECIPIENT_BOUNCED, null, diagnostic, recipients);
    }

    public static DeliveryResult transientFailure(final Reason reason, final String diagnostic) {
        return new DeliveryResult(Status.TRANSIENT_FAILURE, reason, null, diagnostic, List.of());
    }

    /** True when the provider took the message ({@code ACCEPTED} or {@code QUEUED}). */
    public boolean isSuccess() {
        return status == Status.ACCEPTED || status == Status.QUEUED;
    }

    /** True when a later attempt may succeed. */
    public boolean isRetryable() {
        return status == Status.TRANSIENT_FAILURE;
    }

    /** One line, control characters removed, length-capped: safe to log and to show an admin. */
    private static String clean(final String diagnostic) {
        if (diagnostic == null || diagnostic.isBlank()) {
            return null;
        }
        final String oneLine = diagnostic.replaceAll("\\R", " ").replaceAll("\\p{Cc}", " ").trim();
        return oneLine.length() > MAX_DIAGNOSTIC ? oneLine.substring(0, MAX_DIAGNOSTIC) + "…" : oneLine;
    }
}
