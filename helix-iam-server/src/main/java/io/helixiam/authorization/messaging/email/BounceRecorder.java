/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import java.time.Instant;
import java.util.List;

/** Marks the users whose email address bounced permanently ({@link JdbcBounceRecorder}). */
@FunctionalInterface
public interface BounceRecorder {

    /**
     * Marks {@code address} as bounced at {@code at} on the users of {@code realm} (null: outside a realm, the master
     * realm) who have it; returns their user ids.
     */
    List<String> markBounced(String realm, String address, Instant at);
}
