/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import java.time.Duration;
import java.util.List;

/**
 * How credential status (Token Status List) is enforced for one wallet provider (spec §7.6, config
 * {@code statusList}).
 *
 * @param required      a credential without a {@code status} claim is refused ({@code STATUS_REQUIRED})
 * @param onUnavailable what happens when the status cannot be determined; applied by {@link TokenStatusListClient}
 *                      for a status list, and by the verifiers for a status claim with no evaluable mechanism
 * @param maxCache      the longest a verified Status List Token is cached (null: 900 s); a shorter {@code ttl} wins
 * @param allowedHosts  status list hosts allowed (exact name, case-insensitive); empty or null means any https host
 *                      that passes the outbound guard
 */
public record StatusPolicy(boolean required, OnUnavailable onUnavailable, Duration maxCache,
        List<String> allowedHosts) {

    /** What to do when the status list cannot be fetched or validated. */
    public enum OnUnavailable { FAIL_CLOSED, FAIL_OPEN_WITH_AUDIT }
}
