/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * What to load and how to judge it.
 *
 * @param url               the list's https URL
 * @param format            ETSI TS 119 612 XML (a trusted list or a list of trusted lists) or ETSI TS 119 602 LoTE JSON
 * @param signers           the pinned signer certificates; the list's signature must verify with one of them
 * @param serviceTypes      service type URIs to extract (never empty)
 * @param acceptedStatuses  current statuses that count (XML only); default {@link #DEFAULT_STATUSES}
 * @param territories       for a list of trusted lists: the territories whose lists are read (empty: all)
 * @param previousSequence  the sequence number of the last list accepted, or null: a lower one is refused (rollback)
 */
public record TrustedListSpec(String url, Format format, List<X509Certificate> signers, Set<String> serviceTypes,
                              Set<String> acceptedStatuses, Set<String> territories, Long previousSequence) {

    /** The list formats HelixIAM reads. */
    public enum Format {
        /** ETSI TS 119 612 v2.x XML, signed XAdES/XMLDSig enveloped: a member-state TL or a list of trusted lists. */
        ETSI_119612_XML,
        /** ETSI TS 119 602 V1.1.1 List of Trusted Entities, JSON in a JWS compact serialization (JAdES). */
        ETSI_119602_JSON
    }

    public static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    public static final String RECOGNISED_AT_NATIONAL_LEVEL =
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";
    /**
     * The statuses that count by default: {@code granted} and {@code recognisedatnationallevel} (ETSI TS 119 612 v2.x
     * §5.5.4; the EUDI reference implementation's test lists publish their PID providers with the latter).
     * {@code withdrawn} and {@code deprecatedatnationallevel} never count.
     */
    public static final Set<String> DEFAULT_STATUSES = Set.of(GRANTED, RECOGNISED_AT_NATIONAL_LEVEL);
    /** Statuses that mean "no longer trusted"; refused in {@link #acceptedStatuses}. */
    public static final Set<String> NEVER_ACCEPTED = Set.of(
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel");

    public TrustedListSpec {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(format, "format");
        signers = List.copyOf(signers);
        serviceTypes = Set.copyOf(serviceTypes);
        acceptedStatuses = acceptedStatuses == null || acceptedStatuses.isEmpty() ? DEFAULT_STATUSES
                : Set.copyOf(acceptedStatuses);
        territories = territories == null ? Set.of() : Set.copyOf(territories);
    }

    public static TrustedListSpec of(final String url, final Format format, final List<X509Certificate> signers,
                                     final Set<String> serviceTypes) {
        return new TrustedListSpec(url, format, signers, serviceTypes, null, null, null);
    }

    public TrustedListSpec withAcceptedStatuses(final Set<String> value) {
        return new TrustedListSpec(url, format, signers, serviceTypes, value, territories, previousSequence);
    }

    public TrustedListSpec withTerritories(final Set<String> value) {
        return new TrustedListSpec(url, format, signers, serviceTypes, acceptedStatuses, value, previousSequence);
    }

    public TrustedListSpec withPreviousSequence(final Long value) {
        return new TrustedListSpec(url, format, signers, serviceTypes, acceptedStatuses, territories, value);
    }
}
