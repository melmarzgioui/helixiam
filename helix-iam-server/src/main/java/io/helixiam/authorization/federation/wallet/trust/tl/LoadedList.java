/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * What a load produced. For a single list: its current services of the configured types. For a list of trusted lists:
 * the list's own facts, and one {@link Member} per followed pointer, each loaded and judged on its own (a member that
 * fails does not fail the others; the caller keeps that member's last good state).
 *
 * @param services   current services of every list that loaded (for a list of lists: the loaded members' together)
 * @param issuedAt   the top list's {@code ListIssueDateTime}
 * @param nextUpdate the top list's NextUpdate (capped); for a single list the anchors are fresh until then
 * @param sequence   the top list's sequence number
 * @param listsRead  how many lists were fetched and verified (1 for a single list)
 * @param listOfLists whether the top list is a list of trusted lists
 * @param members    the followed pointers of a list of lists, in list order (empty for a single list)
 */
public record LoadedList(List<ListedService> services, Instant issuedAt, Instant nextUpdate, long sequence,
                         int listsRead, boolean listOfLists, List<Member> members) {

    public LoadedList {
        services = List.copyOf(services);
        members = members == null ? List.of() : List.copyOf(members);
    }

    /** A single list. */
    public LoadedList(final List<ListedService> services, final Instant issuedAt, final Instant nextUpdate,
                      final long sequence, final int listsRead) {
        this(services, issuedAt, nextUpdate, sequence, listsRead, false, List.of());
    }

    /**
     * One pointed-to list of a list of trusted lists. Loaded: its services and facts; not loaded: why
     * ({@code errorKind}, {@code errorMessage}).
     */
    public record Member(String key, String location, String territory, boolean loaded, List<ListedService> services,
                         Long sequence, Instant issuedAt, Instant nextUpdate, TrustedListException.Kind errorKind,
                         String errorMessage) {

        public Member {
            Objects.requireNonNull(key, "key");
            services = services == null ? List.of() : List.copyOf(services);
        }

        static Member loaded(final String location, final String territory, final List<ListedService> services,
                             final long sequence, final Instant issuedAt, final Instant nextUpdate) {
            return new Member(key(location, territory), location, territory, true, services, sequence, issuedAt,
                    nextUpdate, null, null);
        }

        static Member failed(final String location, final String territory, final TrustedListException e) {
            return new Member(key(location, territory), location, territory, false, List.of(), null, null, null,
                    e.kind(), e.getMessage());
        }

        /** The member's identity: SHA-256 (hex) of its location and territory, so a moved list is a new member. */
        public static String key(final String location, final String territory) {
            try {
                final byte[] digest = MessageDigest.getInstance("SHA-256").digest(((location == null ? "" : location)
                        + "\n" + (territory == null ? "" : territory)).getBytes(StandardCharsets.UTF_8));
                return HexFormat.of().formatHex(digest);
            } catch (final NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
