/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import org.w3c.dom.Document;

import java.net.URI;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Loads one configured trusted list source: fetches it, verifies its signature against the pinned signers, checks it
 * is fresh ({@code NextUpdate} not passed) and not older than the last accepted list (sequence number), and extracts
 * the current services of the configured types. A list of trusted lists (ETSI TS 119 612, a {@code TSLType} ending
 * in {@code listofthelists}) is followed one level: each XML pointer (optionally only the configured territories) is
 * fetched and verified with the signer certificates the list of lists names for it, and its services are extracted
 * the same way. Any list that fails fails the whole load: the caller keeps its last good anchors (fail safe).
 */
public final class TrustedListLoader {

    /** Most pointed-to lists followed in one load (the EU LOTL points at about 30 XML lists). */
    public static final int MAX_POINTERS = 64;
    /** Most services kept from one load. */
    public static final int MAX_SERVICES = 10_000;

    private final TrustedListFetcher fetcher;
    private final Clock clock;
    private final long maxBytes;

    public TrustedListLoader(final TrustedListFetcher fetcher, final Clock clock) {
        this(fetcher, clock, SecureXml.DEFAULT_MAX_BYTES);
    }

    public TrustedListLoader(final TrustedListFetcher fetcher, final Clock clock, final long maxBytes) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxBytes = maxBytes;
    }

    /**
     * Loads {@code spec} for {@code realm}.
     *
     * @throws TrustedListException naming why (see {@link TrustedListException.Kind}); nothing partial is returned
     */
    public LoadedList load(final TrustedListSpec spec, final String realm) throws TrustedListException {
        final Instant now = clock.instant();
        requireHttps(spec.url());
        final Etsi119612List top = fetchVerified(spec.format(), spec.url(), spec.signers(), realm);
        checkFresh(top, now);
        if (spec.previousSequence() != null && top.sequence() < spec.previousSequence()) {
            throw new TrustedListException(TrustedListException.Kind.ROLLBACK,
                    "the list's sequence number is lower than that of the last list accepted");
        }
        final List<ListedService> services = new ArrayList<>();
        Instant nextUpdate = top.nextUpdate();
        int read = 1;
        if (spec.format() == TrustedListSpec.Format.ETSI_119612_XML && top.isListOfLists()) {
            int followed = 0;
            for (final Etsi119612List.Pointer pointer : top.pointers()) {
                if (!follows(pointer, spec)) {
                    continue;
                }
                if (++followed > MAX_POINTERS) {
                    throw new TrustedListException(TrustedListException.Kind.POLICY,
                            "the list of trusted lists points at more than " + MAX_POINTERS + " lists");
                }
                requireHttps(pointer.location());
                if (pointer.signers().isEmpty()) {
                    throw new TrustedListException(TrustedListException.Kind.SIGNATURE,
                            "the list of trusted lists names no signer for the " + territory(pointer) + " list");
                }
                final Etsi119612List member = fetchVerified(TrustedListSpec.Format.ETSI_119612_XML,
                        pointer.location(), pointer.signers(), realm);
                if (member.isListOfLists()) {
                    continue; // one level only
                }
                checkFresh(member, now);
                nextUpdate = nextUpdate.isBefore(member.nextUpdate()) ? nextUpdate : member.nextUpdate();
                read++;
                extract(member, spec, now, services);
            }
        } else {
            extract(top, spec, now, services);
        }
        return new LoadedList(services, top.issued(), nextUpdate, top.sequence(), read);
    }

    /** XML pointers to other (non list-of-lists) lists, in the configured territories. */
    private static boolean follows(final Etsi119612List.Pointer pointer, final TrustedListSpec spec) {
        if (pointer.location() == null || pointer.location().isBlank()) {
            return false;
        }
        if (pointer.type() != null
                && pointer.type().toLowerCase(Locale.ROOT).endsWith(Etsi119612List.LIST_OF_LISTS_SUFFIX)) {
            return false;
        }
        if (pointer.mimeType() != null && !pointer.mimeType().toLowerCase(Locale.ROOT).contains("xml")) {
            return false; // the PDF rendition of the same list
        }
        return spec.territories().isEmpty() || pointer.territory() != null
                && spec.territories().contains(pointer.territory().toUpperCase(Locale.ROOT));
    }

    private Etsi119612List fetchVerified(final TrustedListSpec.Format format, final String url,
                                         final List<X509Certificate> signers, final String realm)
            throws TrustedListException {
        final byte[] body = fetcher.fetch(url, realm);
        if (body.length > maxBytes) {
            throw new TrustedListException(TrustedListException.Kind.TOO_LARGE, "the list is larger than the size cap");
        }
        if (format == TrustedListSpec.Format.ETSI_119602_JSON) {
            final LoteJsonList.Verified verified = LoteJsonList.read(body, signers);
            checkSigner(verified.signer(), verified.list().issued());
            return verified.list();
        }
        final Document doc = SecureXml.parse(body, maxBytes);
        final X509Certificate signer = XmlListSignature.verify(doc, signers);
        final Etsi119612List list = Etsi119612List.read(doc.getDocumentElement());
        checkSigner(signer, list.issued());
        return list;
    }

    /** The pinned signer must have been valid when the list was issued (the list is signed at issue). */
    private static void checkSigner(final X509Certificate signer, final Instant issued) throws TrustedListException {
        try {
            signer.checkValidity(Date.from(issued));
        } catch (final CertificateExpiredException | CertificateNotYetValidException e) {
            throw new TrustedListException(TrustedListException.Kind.SIGNER,
                    "the signer certificate was not valid when the list was issued");
        }
    }

    private static void checkFresh(final Etsi119612List list, final Instant now) throws TrustedListException {
        if (list.nextUpdate() == null) {
            throw new TrustedListException(TrustedListException.Kind.EXPIRED,
                    "the list has no NextUpdate (a closed list)");
        }
        if (list.nextUpdate().isBefore(now)) {
            throw new TrustedListException(TrustedListException.Kind.EXPIRED, "the list's NextUpdate has passed");
        }
    }

    private static void extract(final Etsi119612List list, final TrustedListSpec spec, final Instant now,
                                final List<ListedService> out) throws TrustedListException {
        final boolean xml = spec.format() == TrustedListSpec.Format.ETSI_119612_XML;
        for (final Etsi119612List.Service s : list.services()) {
            if (s.type() == null || !spec.serviceTypes().contains(s.type())) {
                continue;
            }
            if (xml && (s.status() == null || !spec.acceptedStatuses().contains(s.status())
                    || s.statusStart() != null && s.statusStart().isAfter(now))) {
                continue;
            }
            for (final X509Certificate cert : s.certificates()) {
                if (out.size() >= MAX_SERVICES) {
                    throw new TrustedListException(TrustedListException.Kind.POLICY,
                            "the lists hold more than " + MAX_SERVICES + " matching services");
                }
                out.add(new ListedService(cert, s.type(), s.name(), s.provider(),
                        s.country() != null ? s.country() : list.territory(), s.status()));
            }
        }
    }

    private static void requireHttps(final String url) throws TrustedListException {
        final URI uri;
        try {
            uri = new URI(url.trim());
        } catch (final Exception e) {
            throw new TrustedListException(TrustedListException.Kind.POLICY, "the list URL is not a valid URL");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null) {
            throw new TrustedListException(TrustedListException.Kind.POLICY,
                    "the list URL must be an https URL without user information");
        }
    }

    private static String territory(final Etsi119612List.Pointer pointer) {
        return pointer.territory() == null ? "unnamed" : pointer.territory().replaceAll("[^A-Za-z]", "");
    }
}
