/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.emailverification;

/**
 * C3: delivers an email-verification link. The default implementation emails it through the realm's email provider
 * (SMTP or HTTP driver), falling back to the global SMTP notifier. Returns whether the message was handed to a
 * provider.
 */
@FunctionalInterface
public interface EmailVerificationSender {

    boolean send(EmailVerificationMessage message);
}
