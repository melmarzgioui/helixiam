/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.util.List;

/**
 * One configured trusted list source of a realm and the state of its last refresh (one row of
 * {@code trusted_list_source}).
 *
 * @param config the admin's settings
 * @param state  what the last refreshes produced
 */
public record TrustedListSource(String id, String realmId, Config config, State state) {

    /** The admin's settings; lists are never null. */
    public record Config(String name, String url, TrustedListSpec.Format format, String signerCertificates,
                         List<String> serviceTypes, List<String> acceptedStatuses, List<String> territories,
                         int graceHours, boolean enabled) {

        public Config {
            serviceTypes = serviceTypes == null ? List.of() : List.copyOf(serviceTypes);
            acceptedStatuses = acceptedStatuses == null ? List.of() : List.copyOf(acceptedStatuses);
            territories = territories == null ? List.of() : List.copyOf(territories);
        }

        /** Whether {@code other} changes what is loaded (anything but the name, grace and the switch). */
        public boolean sameList(final Config other) {
            return url.equals(other.url) && format == other.format
                    && signerCertificates.equals(other.signerCertificates) && serviceTypes.equals(other.serviceTypes)
                    && acceptedStatuses.equals(other.acceptedStatuses) && territories.equals(other.territories);
        }
    }

    /**
     * The refresh state; times are epoch milliseconds, null when not (yet) known.
     *
     * @param status       the stored status ({@link TrustedListHealth.Status} name) as of the last write
     * @param nextUpdate   the last good list's (earliest) NextUpdate
     * @param servicesJson the last good list's services ({@link ServicesCodec}), null when none
     * @param version       moves with every write (replicas reload what moved)
     * @param configVersion moves with every settings change (a refresh started under older settings is discarded)
     */
    public record State(String status, Long lastAttemptAt, Long lastSuccessAt, Long listIssuedAt, Long nextUpdate,
                        Long nextRefreshAt, Long sequenceNumber, Integer listsRead, String lastError,
                        String servicesJson, long version, long configVersion, long createdAt, long updatedAt) {
    }
}
