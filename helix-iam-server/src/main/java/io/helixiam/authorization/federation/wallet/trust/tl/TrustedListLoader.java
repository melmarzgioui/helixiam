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
import java.time.Duration;
import java.time.Period;
import java.time.ZoneOffset;
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
 * the same way. A failure of the top list fails the load (the caller keeps its last good state); a failure of one
 * pointed-to list fails that member only ({@link LoadedList.Member}), and the caller keeps that member's last good
 * state on its own.
 */
public final class TrustedListLoader {

    /** Most pointed-to lists followed in one load (the EU LOTL points at about 30 XML lists). */
    public static final int MAX_POINTERS = 64;
    /** Most services kept from one load. */
    public static final int MAX_SERVICES = 10_000;

    /**
     * Policy knobs.
     *
     * @param signerExpiryGrace how long after its notAfter a signer certificate may still verify a list that was issued
     *                          while it was valid. Lists are signed at issue and stay valid until NextUpdate, so a
     *                          signer may lapse before the list does (the EUDI reference implementation's test LOTL of
     *                          2026-04-30 was signed by a certificate that expired on 2026-07-04); beyond the grace the
     *                          list is refused however it is dated, so a long-expired (possibly leaked) key cannot sign
     *                          a backdated list. Default 180 days ({@code helix.wallet.trusted-lists.signer-expiry-grace-days}).
     * @param maxValidity       the longest a list counts after its ListIssueDateTime: its NextUpdate is capped there
     *                          (ETSI TS 119 612 §5.3.14: NextUpdate at most six months after issue). Default six months
     *                          ({@code helix.wallet.trusted-lists.max-validity-months}).
     */
    public record Settings(Duration signerExpiryGrace, Period maxValidity) {
        public static final Settings DEFAULTS = new Settings(Duration.ofDays(180), Period.ofMonths(6));

        public Settings {
            Objects.requireNonNull(signerExpiryGrace, "signerExpiryGrace");
            Objects.requireNonNull(maxValidity, "maxValidity");
        }
    }

    private final TrustedListFetcher fetcher;
    private final Clock clock;
    private final long maxBytes;
    private final Settings settings;

    public TrustedListLoader(final TrustedListFetcher fetcher, final Clock clock) {
        this(fetcher, clock, SecureXml.DEFAULT_MAX_BYTES);
    }

    public TrustedListLoader(final TrustedListFetcher fetcher, final Clock clock, final long maxBytes) {
        this(fetcher, clock, maxBytes, Settings.DEFAULTS);
    }

    public TrustedListLoader(final TrustedListFetcher fetcher, final Clock clock, final long maxBytes,
                             final Settings settings) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxBytes = maxBytes;
        this.settings = Objects.requireNonNull(settings, "settings");
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
        if (spec.format() == TrustedListSpec.Format.ETSI_119612_XML && top.isListOfLists()) {
            final List<LoadedList.Member> members = new ArrayList<>();
            final List<ListedService> all = new ArrayList<>();
            int followed = 0;
            for (final Etsi119612List.Pointer pointer : top.pointers()) {
                if (!follows(pointer, spec)) {
                    continue;
                }
                if (++followed > MAX_POINTERS) {
                    throw new TrustedListException(TrustedListException.Kind.POLICY,
                            "the list of trusted lists points at more than " + MAX_POINTERS + " lists");
                }
                final LoadedList.Member member = member(pointer, spec, now, realm);
                if (member == null) {
                    continue; // a pointer to another list of lists: one level only
                }
                members.add(member);
                if (member.loaded()) {
                    if (all.size() + member.services().size() > MAX_SERVICES) {
                        throw new TrustedListException(TrustedListException.Kind.POLICY,
                                "the lists hold more than " + MAX_SERVICES + " matching services");
                    }
                    all.addAll(member.services());
                }
            }
            final int read = 1 + (int) members.stream().filter(LoadedList.Member::loaded).count();
            return new LoadedList(all, top.issued(), top.nextUpdate(), top.sequence(), read, true, members);
        }
        final List<ListedService> services = new ArrayList<>();
        extract(top, spec, now, services);
        return new LoadedList(services, top.issued(), top.nextUpdate(), top.sequence(), 1);
    }

    /**
     * One pointed-to list, judged on its own: https, verified with the signers the list of lists names for it, its
     * territory and type matching the pointer, fresh, and not older than its last accepted list. Null for a pointer
     * that turns out to be another list of lists.
     */
    private LoadedList.Member member(final Etsi119612List.Pointer pointer, final TrustedListSpec spec,
                                     final Instant now, final String realm) {
        final String location = pointer.location().trim();
        final String territory = pointer.territory();
        try {
            requireHttps(location);
            if (pointer.signers().isEmpty()) {
                throw new TrustedListException(TrustedListException.Kind.SIGNATURE,
                        "the list of trusted lists names no signer for this list");
            }
            final Etsi119612List member = fetchVerified(TrustedListSpec.Format.ETSI_119612_XML, location,
                    pointer.signers(), realm);
            if (member.isListOfLists()) {
                return null;
            }
            if (territory != null && !territory.equalsIgnoreCase(member.territory())) {
                throw new TrustedListException(TrustedListException.Kind.MALFORMED,
                        "the list's SchemeTerritory does not match the territory the list of lists names for it");
            }
            if (pointer.type() != null && !pointer.type().equals(member.type())) {
                throw new TrustedListException(TrustedListException.Kind.MALFORMED,
                        "the list's TSLType does not match the type the list of lists names for it");
            }
            checkFresh(member, now);
            final Long previous = spec.previousMemberSequences().get(LoadedList.Member.key(location, territory));
            if (previous != null && member.sequence() < previous) {
                throw new TrustedListException(TrustedListException.Kind.ROLLBACK,
                        "the list's sequence number is lower than that of its last list accepted");
            }
            final List<ListedService> services = new ArrayList<>();
            extract(member, spec, now, services);
            return LoadedList.Member.loaded(location, territory, services, member.sequence(), member.issued(),
                    member.nextUpdate());
        } catch (final TrustedListException e) {
            return LoadedList.Member.failed(location, territory, e);
        }
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
        final List<X509Certificate> usable = signers.stream().filter(c -> PemCertificates.keyProblem(c) == null)
                .toList();
        if (usable.isEmpty()) {
            throw new TrustedListException(TrustedListException.Kind.SIGNER,
                    "no signer certificate has an acceptable key (RSA 2048 bits or more, or EC P-256 or stronger)");
        }
        final byte[] body = fetcher.fetch(url, realm);
        if (body.length > maxBytes) {
            throw new TrustedListException(TrustedListException.Kind.TOO_LARGE, "the list is larger than the size cap");
        }
        if (format == TrustedListSpec.Format.ETSI_119602_JSON) {
            final LoteJsonList.Verified verified = LoteJsonList.read(body, usable);
            checkSigner(verified.signer(), verified.list().issued());
            return capped(verified.list());
        }
        final Document doc = SecureXml.parse(body, maxBytes);
        final X509Certificate signer = XmlListSignature.verify(doc, usable);
        final Etsi119612List list = Etsi119612List.read(doc.getDocumentElement());
        checkSigner(signer, list.issued());
        return capped(list);
    }

    /** The list with its NextUpdate capped at ListIssueDateTime plus {@link Settings#maxValidity} (UTC calendar). */
    private Etsi119612List capped(final Etsi119612List list) {
        final Instant cap = list.issued().atZone(ZoneOffset.UTC).plus(settings.maxValidity()).toInstant();
        if (list.nextUpdate() == null || !list.nextUpdate().isAfter(cap)) {
            return list;
        }
        return new Etsi119612List(list.type(), list.territory(), list.sequence(), list.issued(), cap, list.pointers(),
                list.services());
    }

    /**
     * The signer must have been valid when the list was issued (the list is signed at issue), and must not have expired
     * longer ago than {@link Settings#signerExpiryGrace} (whatever date the list claims).
     */
    private void checkSigner(final X509Certificate signer, final Instant issued) throws TrustedListException {
        try {
            signer.checkValidity(Date.from(issued));
        } catch (final CertificateExpiredException | CertificateNotYetValidException e) {
            throw new TrustedListException(TrustedListException.Kind.SIGNER,
                    "the signer certificate was not valid when the list was issued");
        }
        if (clock.instant().isAfter(signer.getNotAfter().toInstant().plus(settings.signerExpiryGrace()))) {
            throw new TrustedListException(TrustedListException.Kind.SIGNER, "the signer certificate expired more than "
                    + settings.signerExpiryGrace().toDays() + " days ago; pin the publisher's current certificate");
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
            // LoTE: no status means listing is the trust decision; a status must be an accepted one
            if (!xml && s.status() != null && !spec.acceptedStatuses().contains(s.status())) {
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
}
