/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import java.time.Duration;
import java.util.List;

/**
 * How credential status (Token Status List) is enforced for one wallet provider. Behaviour is added in Task 10.
 */
public record StatusPolicy(boolean required, OnUnavailable onUnavailable, Duration maxCache,
        List<String> allowedHosts) {

    /** What to do when the status list cannot be fetched or validated. */
    public enum OnUnavailable { FAIL_CLOSED, FAIL_OPEN_WITH_AUDIT }
}
