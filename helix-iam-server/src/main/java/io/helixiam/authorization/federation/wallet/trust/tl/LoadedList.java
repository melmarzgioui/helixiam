/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.time.Instant;
import java.util.List;

/**
 * What a load produced: the current services of the configured types, from every list read (for a list of trusted
 * lists: the pointed-to lists), all signature-verified.
 *
 * @param services   current services of the configured types and statuses
 * @param issuedAt   the top list's {@code ListIssueDateTime}
 * @param nextUpdate the earliest {@code NextUpdate} of every list read: the anchors are fresh until then
 * @param sequence   the top list's sequence number
 * @param listsRead  how many lists were fetched and verified (1 for a single list)
 */
public record LoadedList(List<ListedService> services, Instant issuedAt, Instant nextUpdate, long sequence,
                         int listsRead) {

    public LoadedList {
        services = List.copyOf(services);
    }
}
