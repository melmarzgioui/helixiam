/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.push;

import java.util.Optional;

/**
 * Helix IAM E4.3: store for push-approval requests, keyed by id. The browser starts the approval and
 * polls it while the phone (possibly on another node) resolves it, so this must be shared across
 * publisher instances for horizontal scale. Default is in-process ({@link InMemoryPushApprovalStore});
 * a Redis-backed impl drops in via this interface (mirroring the QR + session stores).
 */
public interface PushApprovalStore {

    void save(PushApproval approval);

    Optional<PushApproval> find(String id);

    void remove(String id);
}
