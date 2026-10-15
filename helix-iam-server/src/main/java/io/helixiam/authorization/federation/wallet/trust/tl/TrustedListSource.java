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
     * @param listOfLists   the last good list is a list of trusted lists: its anchors come from its members
     * @param settingsMac   {@link TrustedListIntegrity} MAC of the settings, null without DB_ENCRYPTION
     * @param servicesMac   {@link TrustedListIntegrity} MAC of the stored services, null without DB_ENCRYPTION
     */
    public record State(String status, Long lastAttemptAt, Long lastSuccessAt, Long listIssuedAt, Long nextUpdate,
                        Long nextRefreshAt, Long sequenceNumber, Integer listsRead, String lastError,
                        String servicesJson, long version, long configVersion, boolean listOfLists, long createdAt,
                        long updatedAt, String settingsMac, String servicesMac) {
    }

    /**
     * One member of a list of trusted lists (a row of {@code trusted_list_member}); times epoch milliseconds.
     *
     * @param status       the stored status ({@link TrustedListHealth.Status} name) as of the last write
     * @param servicesJson the member's last good services, null when none
     */
    public record Member(String sourceId, String key, String location, String territory, String status,
                         String servicesJson, Long sequenceNumber, Long listIssuedAt, Long nextUpdate,
                         Long lastAttemptAt, Long lastSuccessAt, String lastError, long version,
                         String servicesMac, String tslType) {
    }
}
