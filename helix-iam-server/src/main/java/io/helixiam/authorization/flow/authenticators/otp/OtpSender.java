/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators.otp;

/**
 * Helix IAM E3.1: delivers a one-time code to a user over a channel (SMS gateway, email). Keeps
 * the OTP authenticators decoupled from the concrete provider; the live adapters resolve the
 * user's phone/email and dispatch via the notification starter / an SMS gateway.
 */
@FunctionalInterface
public interface OtpSender {
    void send(String userId, String code);
}
