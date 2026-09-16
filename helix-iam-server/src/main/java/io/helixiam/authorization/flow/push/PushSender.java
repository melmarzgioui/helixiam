/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.push;

/**
 * Helix IAM E4.3: transport seam for delivering a {@link PushMessage} to a user's enrolled device(s)
 * — implemented by FCM (Android) / APNs (iOS) adapters. The dev default {@link LoggingPushSender}
 * just logs, so the flow is exercisable without push credentials (mirrors the OtpSender seam in E3.1).
 */
@FunctionalInterface
public interface PushSender {

    void send(PushMessage message);
}
