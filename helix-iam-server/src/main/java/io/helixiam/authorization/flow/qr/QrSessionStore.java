/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.qr;

import java.util.Optional;

/**
 * Helix IAM E4.2: store for cross-device QR-login sessions, keyed by session id. The browser opens a
 * session, the phone confirms it (different request, possibly different node), and the browser
 * consumes it — so this must be shared across publisher instances for horizontal scale. The default
 * is in-process ({@link InMemoryQrSessionStore}); a Redis-backed impl drops in via this interface
 * (mirroring the pluggable session/token stores from E1.2).
 */
public interface QrSessionStore {

    void save(QrSession session);

    Optional<QrSession> find(String id);

    void remove(String id);
}
