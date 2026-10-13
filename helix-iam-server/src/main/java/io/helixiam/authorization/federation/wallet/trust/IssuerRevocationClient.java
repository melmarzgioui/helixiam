/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;
import io.helixiam.common.net.PinnedHttpFetcher.FetchException;
import io.helixiam.common.net.PinnedHttpFetcher.Limits;
import io.helixiam.common.net.SingleFlight;
import io.helixiam.common.net.SsrfBlockedException;
import io.helixiam.common.net.UnresolvableHostException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * HelixIAM's own transport for wallet issuer-certificate revocation (OCSP and CRL), replacing the JDK
 * {@link PKIXRevocationChecker}'s built-in network fetching while keeping the JDK's validation of what was fetched.
 *
 * <p><b>Transport.</b> Every OCSP responder (AIA) and CRL distribution point URL named in a certificate goes through
 * {@link PinnedHttpFetcher}: {@link OutboundUrlGuard} first (http and https only; loopback, private, link-local and
 * metadata addresses refused), one DNS resolution and a connection to the validated address (no second resolution,
 * so no DNS rebinding), no redirects, connect {@value #CONNECT_TIMEOUT_SECONDS} s and {@value #FETCH_TIMEOUT_SECONDS}
 * s in total per fetch (DNS included), at most {@value #MAX_OCSP_BYTES} bytes for an OCSP response and
 * {@link Settings#maxCrlBytes()} for a CRL. Plain http is expected and fine: CRLs and OCSP responses are signed, and
 * that signature (checked below) is their integrity. One certificate tries at most {@value #MAX_URLS_PER_KIND} OCSP
 * and {@value #MAX_URLS_PER_KIND} CRL URLs, and one chain spends at most {@link #CHAIN_BUDGET} on fetching.
 *
 * <p><b>Validation.</b> The JDK validates what was fetched and never fetches anything itself. A fetched OCSP response
 * is handed to the JDK PKIX revocation checker with {@link PKIXRevocationChecker#setOcspResponses} and
 * {@code NO_FALLBACK} (OCSP only): with a response supplied for the one certificate checked, the JDK never contacts a
 * responder. A fetched CRL is first checked by {@link #crlUsable} (issuer name and key identifier, cRLSign, signature
 * algorithm and signature, thisUpdate / nextUpdate within the JDK's 15-minute skew, no unknown critical extension,
 * no delta / indirect / partial CRL) and then handed to the JDK's legacy CRL checker in a {@link CertStore}. Not
 * {@code PKIXRevocationChecker}: its fallback to fetching every distribution point of the certificate (unpinned,
 * unbounded) is hard-wired on whenever it cannot approve a CRL, whereas the legacy checker fetches nothing while
 * {@code com.sun.security.enableCRLDP} is off (forced off at startup) and the other JVM settings in
 * {@link #jdkCannotFetch} are at their defaults; if an operator changes them, CRLs are not evaluated at all (logged).
 * Each check runs on a one-certificate path whose trust anchor is that certificate's issuer (the path was already
 * validated end to end), so every certificate gets its own answer.
 *
 * <p><b>Concurrency.</b> Concurrent logins needing the same CRL or OCSP answer share one download ({@link SingleFlight});
 * all fetches together are capped by the transport's {@link io.helixiam.common.net.FetchLimiter}. A URL that served
 * something that is not a CRL, or a CRL over the size cap, is not downloaded again for {@link #JUNK_TTL}.
 *
 * <p><b>Cache.</b> OCSP responses and CRLs that gave a definite answer (good or revoked) are cached until their
 * {@code nextUpdate} (a CRL until {@code nextUpdate} plus the {@link #CRL_CLOCK_SKEW} it is still accepted for; never
 * longer than {@link #MAX_CACHE_TTL}; without {@code nextUpdate}: not cached), bounded by
 * {@link Settings#cacheMaxEntries()} and {@link Settings#cacheMaxBytes()} (an OCSP response counts its encoded bytes, a
 * CRL its estimated parsed heap, {@link #crlHeapEstimate}), least recently used
 * evicted first. A cached answer is validated again at every use.
 */
public final class IssuerRevocationClient {

    public static final int CONNECT_TIMEOUT_SECONDS = 3;
    public static final int FETCH_TIMEOUT_SECONDS = 5;
    public static final int MAX_OCSP_BYTES = 64 * 1024;
    /** Most fetching one chain's revocation check may spend; after it, remaining certificates are undetermined. */
    public static final Duration CHAIN_BUDGET = Duration.ofSeconds(10);
    /** Longest a cached OCSP response or CRL is used, whatever its {@code nextUpdate}. */
    public static final Duration MAX_CACHE_TTL = Duration.ofHours(24);
    static final int MAX_URLS_PER_KIND = 2;
    /** How long a URL that served something that is not a usable-size CRL is not downloaded again. */
    static final Duration JUNK_TTL = Duration.ofSeconds(60);
    private static final int MAX_JUNK_ENTRIES = 256;
    /** Below this much remaining budget, no new fetch is started. */
    private static final long MIN_FETCH_NANOS = TimeUnit.MILLISECONDS.toNanos(200);
    private static final Set<String> CRL_SIGNATURE_ALGORITHMS = Set.of("SHA256withECDSA", "SHA384withECDSA",
            "SHA512withECDSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "RSASSA-PSS", "Ed25519", "Ed448");
    private static final int CRL_SIGN = 6;
    /**
     * Clock skew tolerated on a CRL's thisUpdate / nextUpdate: exactly the JDK's ({@code RevocationChecker
     * .MAX_CLOCK_SKEW}, 900 000 ms) and no more, so the JDK's CRL selector never drops a CRL accepted here.
     */
    static final Duration CRL_CLOCK_SKEW = Duration.ofMillis(900_000);

    /**
     * Operator settings ({@code helix.wallet.revocation.*}).
     *
     * @param maxCrlBytes     largest CRL downloaded (default 10 MB, at most {@value #MAX_CRL_BYTES_CAP})
     * @param cacheMaxEntries most cached OCSP responses and CRLs together (default 256)
     * @param cacheMaxBytes   most cached bytes, OCSP responses and CRLs together (default 32 MB; a CRL counts its
     *                        estimated parsed heap, see {@link #crlHeapEstimate})
     */
    public record Settings(long maxCrlBytes, int cacheMaxEntries, long cacheMaxBytes) {

        public static final long DEFAULT_MAX_CRL_BYTES = 10L * 1024 * 1024;
        public static final int DEFAULT_CACHE_MAX_ENTRIES = 256;
        public static final long DEFAULT_CACHE_MAX_BYTES = 32L * 1024 * 1024;
        public static final Settings DEFAULTS = new Settings(DEFAULT_MAX_CRL_BYTES, DEFAULT_CACHE_MAX_ENTRIES,
                DEFAULT_CACHE_MAX_BYTES);

        /** The largest {@code max-crl-bytes} accepted: 100 MB. */
        public static final long MAX_CRL_BYTES_CAP = 100L * 1024 * 1024;

        public Settings {
            if (maxCrlBytes <= 0 || maxCrlBytes > MAX_CRL_BYTES_CAP) {
                throw new IllegalArgumentException("helix.wallet.revocation.max-crl-bytes must be between 1 and "
                        + MAX_CRL_BYTES_CAP);
            }
            if (cacheMaxEntries < 0 || cacheMaxBytes < 0) {
                throw new IllegalArgumentException("helix.wallet.revocation cache settings must not be negative");
            }
        }

        public Settings withMaxCrlBytes(final long value) {
            return new Settings(value, cacheMaxEntries, cacheMaxBytes);
        }

        public Settings withCache(final int entries, final long bytes) {
            return new Settings(maxCrlBytes, entries, bytes);
        }
    }

    /** One certificate's revocation status. */
    enum Outcome {
        GOOD, REVOKED,
        /** No source gave a definite answer. */
        UNDETERMINED,
        /** Every source the certificate names was refused by policy (scheme, address, non-URI name). */
        BLOCKED
    }

    /** One source's answer. */
    enum Answer { GOOD, REVOKED, UNDETERMINED, BLOCKED }

    private record Cached(Object value, long bytes, Instant until) {
    }

    private final PinnedHttpFetcher fetcher;
    private final Settings settings;
    private final Clock clock;
    private final Map<String, Cached> cache = new LinkedHashMap<>(16, 0.75f, true);
    private long cachedBytes;
    /** URLs that recently served something that is not a CRL (or too large a one), and until when to skip them. */
    private final Map<String, Instant> junk = new LinkedHashMap<>(16, 0.75f, true);
    /** One download per CRL URL / OCSP request at a time, whatever the number of concurrent logins. */
    private final SingleFlight<String, Download> downloads = new SingleFlight<>();

    /**
     * A download's outcome: the body and what the downloading caller made of it ({@code parsed}, null when it is not
     * usable), or why there is none.
     */
    private record Download(byte[] body, Object parsed, Answer failure, boolean junk) {
        static Download failed(final Answer failure) {
            return new Download(null, null, failure, false);
        }

        static Download notUsable() {
            return new Download(null, null, Answer.UNDETERMINED, true);
        }
    }

    public IssuerRevocationClient(final OutboundUrlGuard guard, final Settings settings, final Clock clock) {
        this(PinnedHttpFetcher.plain(Objects.requireNonNull(guard, "guard")), settings, clock);
    }

    IssuerRevocationClient(final PinnedHttpFetcher fetcher, final Settings settings, final Clock clock) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** The settings in force. */
    public Settings settings() {
        return settings;
    }

    /** Cached OCSP responses and CRLs (tests, metrics). */
    public int cachedEntries() {
        synchronized (cache) {
            return cache.size();
        }
    }

    /** Bytes held by the cache (tests, metrics). */
    public long cachedBytes() {
        synchronized (cache) {
            return cachedBytes;
        }
    }

    /**
     * The revocation status of {@code cert}, issued by {@code issuer}, at {@code at}: OCSP first, then CRL, stopping at
     * the first definite answer. Fetches stop at {@code deadlineNanos} ({@link System#nanoTime()} based).
     */
    Outcome status(final X509Certificate cert, final TrustAnchor issuer, final Instant at, final long deadlineNanos) {
        final Sources sources = Sources.of(cert);
        int tried = sources.unusable();
        int blocked = sources.unusable();
        for (final String url : sources.ocsp()) {
            tried++;
            final Answer a = ocsp(url, cert, issuer, at, deadlineNanos);
            if (a == Answer.GOOD || a == Answer.REVOKED) {
                return a == Answer.GOOD ? Outcome.GOOD : Outcome.REVOKED;
            }
            blocked += a == Answer.BLOCKED ? 1 : 0;
        }
        for (final String url : sources.crl()) {
            tried++;
            final Answer a = crl(url, cert, issuer, at, deadlineNanos);
            if (a == Answer.GOOD || a == Answer.REVOKED) {
                return a == Answer.GOOD ? Outcome.GOOD : Outcome.REVOKED;
            }
            blocked += a == Answer.BLOCKED ? 1 : 0;
        }
        return tried > 0 && blocked == tried ? Outcome.BLOCKED : Outcome.UNDETERMINED;
    }

    // ------------------------------------------------------------------------------------------- OCSP

    private Answer ocsp(final String url, final X509Certificate cert, final TrustAnchor issuer, final Instant at,
            final long deadlineNanos) {
        if (!httpScheme(url)) {
            return Answer.BLOCKED;
        }
        final X509Certificate issuerCert = issuer.getTrustedCert();
        if (issuerCert == null) {
            return Answer.UNDETERMINED; // a key-only anchor: no issuer certificate to build the OCSP CertID from
        }
        final String key;
        try {
            key = "ocsp|" + url + "|" + fingerprint(cert.getEncoded()) + "|"
                    + fingerprint(issuerCert.getPublicKey().getEncoded());
        } catch (final GeneralSecurityException e) {
            return Answer.UNDETERMINED;
        }
        final byte[] cached = (byte[]) cached(key);
        if (cached != null) {
            final Answer a = jdkOcsp(cert, issuer, cached, at);
            if (a == Answer.GOOD || a == Answer.REVOKED) {
                return a;
            }
            evict(key);
        }
        final CertificateID id;
        final byte[] request;
        try {
            id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());
            request = new OCSPReqBuilder().addRequest(id).build().getEncoded();
        } catch (final Exception e) {
            return Answer.UNDETERMINED;
        }
        final Limits limits = limits(MAX_OCSP_BYTES, deadlineNanos);
        if (limits == null) {
            return Answer.UNDETERMINED;
        }
        // the downloading caller caches a definite answer before the shared download ends, so a caller arriving just
        // after it finds the cache instead of downloading again
        final Download d = download(key, limits, () -> fetcher.post(url, Map.of("Content-Type",
                "application/ocsp-request", "Accept", "application/ocsp-response"), request, limits), body -> {
                    final Answer a = jdkOcsp(cert, issuer, body, at);
                    if (a == Answer.GOOD || a == Answer.REVOKED) {
                        remember(key, body, body.length, ocspNextUpdate(body, id));
                    }
                    return body;
                });
        if (d.body() == null) {
            return d.failure();
        }
        return jdkOcsp(cert, issuer, d.body(), at);
    }

    /** The JDK's verdict on {@code response} for {@code cert} (signature, responder, CertID, validity window). */
    static Answer jdkOcsp(final X509Certificate cert, final TrustAnchor issuer, final byte[] response,
            final Instant at) {
        return jdk(cert, issuer, at, checker -> {
            checker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK)); // OCSP only
            checker.setOcspResponses(Map.of(cert, response));
        }, null);
    }

    private static Instant ocspNextUpdate(final byte[] response, final CertificateID id) {
        try {
            final BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(response).getResponseObject();
            for (final SingleResp single : basic.getResponses()) {
                if (single.getCertID().equals(id)) {
                    final Date next = single.getNextUpdate();
                    return next == null ? null : next.toInstant();
                }
            }
        } catch (final Exception e) {
            // not cacheable
        }
        return null;
    }

    // ------------------------------------------------------------------------------------------- CRL

    private Answer crl(final String url, final X509Certificate cert, final TrustAnchor issuer, final Instant at,
            final long deadlineNanos) {
        if (!httpScheme(url)) {
            return Answer.BLOCKED;
        }
        final String key = "crl|" + url;
        final X509CRL cached = (X509CRL) cached(key);
        if (cached != null) {
            final Answer a = crlUsable(cached, cert, issuer, url, at) ? jdkCrl(cert, issuer, cached, at)
                    : Answer.UNDETERMINED;
            if (a == Answer.GOOD || a == Answer.REVOKED) {
                return a;
            }
            // the cached CRL does not answer for this certificate / instant: try a fresh one
        }
        final Limits limits = limits(settings.maxCrlBytes(), deadlineNanos);
        if (limits == null) {
            return Answer.UNDETERMINED;
        }
        if (isJunk(url)) {
            return Answer.UNDETERMINED;
        }
        final Download d = download(key, limits, () -> fetcher.get(url, Map.of("Accept", "application/pkix-crl"),
                limits), body -> {
                    final X509CRL parsed = parseCrl(body);
                    if (parsed == null) {
                        return null; // not a CRL
                    }
                    // as for OCSP: cached before the shared download ends
                    if (crlUsable(parsed, cert, issuer, url, at)) {
                        final Answer a = jdkCrl(cert, issuer, parsed, at);
                        if (a == Answer.GOOD || a == Answer.REVOKED) {
                            remember(key, parsed, crlHeapEstimate(parsed, body.length), parsed.getNextUpdate().toInstant()
                                    .plus(CRL_CLOCK_SKEW)); // usable until then (see crlUsable)
                        }
                    }
                    return parsed;
                });
        if (d.junk() || d.body() != null && d.parsed() == null) {
            markJunk(url); // not a CRL, or too large: do not download it again on every login
            return Answer.UNDETERMINED;
        }
        if (d.body() == null) {
            return d.failure();
        }
        final X509CRL crl = (X509CRL) d.parsed();
        if (!crlUsable(crl, cert, issuer, url, at)) {
            return Answer.UNDETERMINED;
        }
        return jdkCrl(cert, issuer, crl, at);
    }

    /** Estimated heap held per revoked entry of a parsed CRL, beyond its share of the encoding (bytes). */
    static final int CRL_ENTRY_OVERHEAD = 256;

    /**
     * The heap a parsed CRL is counted as in the cache: three times its encoding (the JDK keeps the encoded CRL, the
     * TBS part and each entry's own encoding) plus {@value #CRL_ENTRY_OVERHEAD} bytes per revoked entry (the entry
     * object, its serial {@code BigInteger}, date, extensions and the lookup map). An estimate on the high side; an
     * OCSP response is cached as its encoded bytes.
     */
    static long crlHeapEstimate(final X509CRL crl, final int encodedLength) {
        final java.util.Set<? extends java.security.cert.X509CRLEntry> revoked = crl.getRevokedCertificates();
        return 3L * encodedLength + (long) (revoked == null ? 0 : revoked.size()) * CRL_ENTRY_OVERHEAD;
    }

    private static X509CRL parseCrl(final byte[] body) {
        try {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(body));
        } catch (final GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    /**
     * The JDK's verdict on {@code crl} for {@code cert}, through its legacy CRL checker (revocation enabled, no
     * {@code PKIXRevocationChecker} given): unlike {@code PKIXRevocationChecker}, whose fallback to the
     * certificate's distribution points is hard-wired on, the legacy checker fetches nothing unless the JVM-wide
     * settings in {@link #jdkCannotFetch} say so, and those are checked first. So a CRL the JDK does not approve is an
     * undetermined status, never a JDK download.
     */
    static Answer jdkCrl(final X509Certificate cert, final TrustAnchor issuer, final X509CRL crl,
            final Instant at) {
        if (!jdkCannotFetch()) {
            if (FETCH_SETTINGS_LOGGED.compareAndSet(false, true)) {
                LOG.error("Wallet issuer CRLs are not evaluated: a JVM setting (com.sun.security.enableCRLDP, "
                        + "com.sun.security.enableAIAcaIssuers, ocsp.enable or "
                        + "com.sun.security.onlyCheckRevocationOfEECert) would let the JDK fetch or skip revocation "
                        + "data itself; remove it");
            }
            return Answer.UNDETERMINED;
        }
        try {
            final CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            final PKIXParameters params = new PKIXParameters(Set.of(issuer));
            params.setDate(Date.from(at));
            params.setRevocationEnabled(true); // the legacy checker: CRLs from the CertStores only
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(List.of(crl))));
            validator.validate(CertificateFactory.getInstance("X.509").generateCertPath(List.of(cert)), params);
            return Answer.GOOD;
        } catch (final CertPathValidatorException e) {
            return e.getReason() == CertPathValidatorException.BasicReason.REVOKED ? Answer.REVOKED
                    : Answer.UNDETERMINED;
        } catch (final GeneralSecurityException | RuntimeException e) {
            return Answer.UNDETERMINED;
        }
    }

    /**
     * True when the JDK will approve {@code crl} for {@code cert} from a {@code CertStore} (mirrors the JDK's
     * {@code DistributionPointFetcher.verifyCRL} and CRL selection, more strictly), so it never falls back to fetching
     * the distribution points itself: a direct, complete CRL of the certificate's issuer, current at {@code at}.
     */
    static boolean crlUsable(final X509CRL crl, final X509Certificate cert, final TrustAnchor issuer,
            final String fetchedUrl, final Instant at) {
        try {
            if (!crl.getIssuerX500Principal().equals(cert.getIssuerX500Principal())) {
                return false;
            }
            final Date thisUpdate = crl.getThisUpdate();
            final Date nextUpdate = crl.getNextUpdate();
            // the JDK's own window, no wider: thisUpdate <= at + skew and nextUpdate >= at - skew (inclusive)
            if (thisUpdate == null || nextUpdate == null || thisUpdate.toInstant().isAfter(at.plus(CRL_CLOCK_SKEW))
                    || nextUpdate.toInstant().isBefore(at.minus(CRL_CLOCK_SKEW))) {
                return false;
            }
            final Set<String> critical = crl.getCriticalExtensionOIDs();
            if (critical != null && critical.stream()
                    .anyMatch(oid -> !oid.equals(Extension.issuingDistributionPoint.getId()))) {
                return false; // delta CRL indicator and anything unknown
            }
            final X509Certificate issuerCert = issuer.getTrustedCert();
            if (issuerCert != null) {
                final boolean[] ku = issuerCert.getKeyUsage();
                if (ku != null && (ku.length <= CRL_SIGN || !ku[CRL_SIGN])) {
                    return false;
                }
            }
            final byte[] certAki = keyIdentifier(cert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
            final byte[] crlAki = keyIdentifier(crl.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
            if (certAki != null && crlAki != null && !Arrays.equals(certAki, crlAki)) {
                return false;
            }
            if (!CRL_SIGNATURE_ALGORITHMS.contains(crl.getSigAlgName())) {
                return false;
            }
            final PublicKey issuerKey = issuerCert != null ? issuerCert.getPublicKey() : issuer.getCAPublicKey();
            crl.verify(issuerKey);
            final DistributionPoint point = distributionPoint(cert, fetchedUrl);
            if (point == null || point.getReasons() != null || point.getCRLIssuer() != null) {
                return false;
            }
            final byte[] idpValue = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
            return idpValue == null || idpCovers(IssuingDistributionPoint.getInstance(unwrap(idpValue)), cert,
                    fetchedUrl);
        } catch (final GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private static boolean idpCovers(final IssuingDistributionPoint idp, final X509Certificate cert,
            final String fetchedUrl) {
        if (idp.isIndirectCRL() || idp.getOnlySomeReasons() != null || idp.onlyContainsAttributeCerts()) {
            return false;
        }
        final boolean ca = cert.getBasicConstraints() != -1;
        if (idp.onlyContainsUserCerts() && ca || idp.onlyContainsCACerts() && !ca) {
            return false;
        }
        final DistributionPointName name = idp.getDistributionPoint();
        if (name == null) {
            return true;
        }
        if (name.getType() != DistributionPointName.FULL_NAME) {
            return false;
        }
        for (final GeneralName n : GeneralNames.getInstance(name.getName()).getNames()) {
            if (n.getTagNo() == GeneralName.uniformResourceIdentifier && fetchedUrl.equals(n.getName().toString())) {
                return true;
            }
        }
        return false;
    }

    /** The certificate's distribution point that names {@code url}. */
    private static DistributionPoint distributionPoint(final X509Certificate cert, final String url) {
        final byte[] value = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (value == null) {
            return null;
        }
        for (final DistributionPoint dp : CRLDistPoint.getInstance(unwrap(value)).getDistributionPoints()) {
            final DistributionPointName name = dp.getDistributionPoint();
            if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                for (final GeneralName n : GeneralNames.getInstance(name.getName()).getNames()) {
                    if (n.getTagNo() == GeneralName.uniformResourceIdentifier && url.equals(n.getName().toString())) {
                        return dp;
                    }
                }
            }
        }
        return null;
    }

    private static byte[] keyIdentifier(final byte[] extensionValue) {
        if (extensionValue == null) {
            return null;
        }
        return AuthorityKeyIdentifier.getInstance(unwrap(extensionValue)).getKeyIdentifierOctets();
    }

    // ------------------------------------------------------------------------------------------- JDK

    private static final org.apache.logging.log4j.Logger LOG =
            org.apache.logging.log4j.LogManager.getLogger(IssuerRevocationClient.class);
    private static final java.util.concurrent.atomic.AtomicBoolean FETCH_SETTINGS_LOGGED =
            new java.util.concurrent.atomic.AtomicBoolean();

    /**
     * True when the JDK's legacy CRL checker, which {@link #jdkCrl} uses, cannot open a connection of its own: its
     * distribution-point fetching ({@code com.sun.security.enableCRLDP}, forced to {@code false} at startup by
     * {@code RevocationTimeouts}), OCSP ({@code ocsp.enable}) and AIA certificate fetching
     * ({@code com.sun.security.enableAIAcaIssuers}) are off, and it checks CA certificates too
     * ({@code com.sun.security.onlyCheckRevocationOfEECert}). These are JVM-wide settings an operator could change.
     */
    static boolean jdkCannotFetch() {
        return !Boolean.getBoolean("com.sun.security.enableCRLDP")
                && !Boolean.getBoolean("com.sun.security.enableAIAcaIssuers")
                && !"true".equalsIgnoreCase(java.security.Security.getProperty("ocsp.enable"))
                && !"true".equalsIgnoreCase(java.security.Security.getProperty(
                        "com.sun.security.onlyCheckRevocationOfEECert"));
    }

    @FunctionalInterface
    private interface CheckerSetup {
        void apply(PKIXRevocationChecker checker);
    }

    /**
     * The JDK PKIX verdict on the one-certificate path {@code [cert]} anchored at its issuer, with the revocation
     * checker configured by {@code setup} (and {@code crls}). The path itself was already validated end to end.
     */
    private static Answer jdk(final X509Certificate cert, final TrustAnchor issuer, final Instant at,
            final CheckerSetup setup, final CertStore crls) {
        try {
            final CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            final PKIXRevocationChecker checker = (PKIXRevocationChecker) validator.getRevocationChecker();
            setup.apply(checker);
            final PKIXParameters params = new PKIXParameters(Set.of(issuer));
            params.setDate(Date.from(at));
            params.setRevocationEnabled(true);
            params.addCertPathChecker(checker);
            if (crls != null) {
                params.addCertStore(crls);
            }
            validator.validate(CertificateFactory.getInstance("X.509").generateCertPath(List.of(cert)), params);
            return Answer.GOOD;
        } catch (final CertPathValidatorException e) {
            return e.getReason() == CertPathValidatorException.BasicReason.REVOKED ? Answer.REVOKED
                    : Answer.UNDETERMINED;
        } catch (final GeneralSecurityException | RuntimeException e) {
            return Answer.UNDETERMINED;
        }
    }

    @FunctionalInterface
    private interface Fetch {
        PinnedHttpFetcher.Response call() throws FetchException;
    }

    /**
     * One download, shared with every concurrent caller asking for the same {@code key} ({@link SingleFlight}); a
     * caller waits for a shared download at most as long as its own limits allow.
     */
    private Download download(final String key, final Limits limits, final Fetch fetch,
            final java.util.function.Function<byte[], Object> prepare) {
        try {
            return downloads.run(key, limits.totalTimeout(), () -> {
                try {
                    final PinnedHttpFetcher.Response r = fetch.call();
                    if (r.status() != 200) {
                        return Download.failed(Answer.UNDETERMINED);
                    }
                    return new Download(r.body(), prepare.apply(r.body()), null, false);
                } catch (final UnresolvableHostException e) {
                    return Download.failed(Answer.UNDETERMINED);
                } catch (final SsrfBlockedException e) {
                    return Download.failed(Answer.BLOCKED);
                } catch (final FetchException e) {
                    return e.kind() == FetchException.Kind.TOO_LARGE ? Download.notUsable()
                            : Download.failed(Answer.UNDETERMINED);
                }
            });
        } catch (final Exception e) {
            return Download.failed(Answer.UNDETERMINED); // our wait for the shared download timed out
        }
    }

    private boolean isJunk(final String url) {
        synchronized (junk) {
            final Instant until = junk.get(url);
            if (until == null) {
                return false;
            }
            if (!clock.instant().isBefore(until)) {
                junk.remove(url);
                return false;
            }
            return true;
        }
    }

    private void markJunk(final String url) {
        synchronized (junk) {
            junk.put(url, clock.instant().plus(JUNK_TTL));
            final var it = junk.keySet().iterator();
            while (junk.size() > MAX_JUNK_ENTRIES && it.hasNext()) {
                it.next();
                it.remove();
            }
        }
    }

    // ------------------------------------------------------------------------------------------- cache

    private Object cached(final String key) {
        synchronized (cache) {
            final Cached c = cache.get(key);
            if (c == null) {
                return null;
            }
            if (!clock.instant().isBefore(c.until())) {
                remove(key);
                return null;
            }
            return c.value();
        }
    }

    private void evict(final String key) {
        synchronized (cache) {
            remove(key);
        }
    }

    private void remember(final String key, final Object value, final long bytes, final Instant nextUpdate) {
        if (nextUpdate == null || settings.cacheMaxEntries() == 0 || bytes > settings.cacheMaxBytes()) {
            return;
        }
        final Instant now = clock.instant();
        final Instant cap = now.plus(MAX_CACHE_TTL);
        final Instant until = nextUpdate.isBefore(cap) ? nextUpdate : cap;
        if (!now.isBefore(until)) {
            return;
        }
        synchronized (cache) {
            remove(key);
            cache.put(key, new Cached(value, bytes, until));
            cachedBytes += bytes;
            final var it = cache.entrySet().iterator();
            while ((cache.size() > settings.cacheMaxEntries() || cachedBytes > settings.cacheMaxBytes())
                    && it.hasNext()) {
                final Map.Entry<String, Cached> eldest = it.next();
                cachedBytes -= eldest.getValue().bytes();
                it.remove();
            }
        }
    }

    /** Caller holds the cache lock. */
    private void remove(final String key) {
        final Cached old = cache.remove(key);
        if (old != null) {
            cachedBytes -= old.bytes();
        }
    }

    // ------------------------------------------------------------------------------------------- helpers

    /** Fetch limits within the chain budget, or null when too little budget is left to start a fetch. */
    private static Limits limits(final long maxBytes, final long deadlineNanos) {
        final long remaining = deadlineNanos - System.nanoTime();
        if (remaining < MIN_FETCH_NANOS) {
            return null;
        }
        final Duration total = Duration.ofNanos(Math.min(remaining, TimeUnit.SECONDS.toNanos(FETCH_TIMEOUT_SECONDS)));
        return new Limits(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS), total, maxBytes);
    }

    private static boolean httpScheme(final String url) {
        return url.regionMatches(true, 0, "http://", 0, 7) || url.regionMatches(true, 0, "https://", 0, 8);
    }

    private static String fingerprint(final byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static ASN1Primitive unwrap(final byte[] extensionValue) {
        try {
            return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extensionValue).getOctets());
        } catch (final IOException e) {
            throw new IllegalArgumentException("malformed extension");
        }
    }

    /**
     * The revocation sources a certificate names: OCSP responder and CRL distribution point URIs (at most
     * {@value #MAX_URLS_PER_KIND} each, in certificate order), and how many named sources can never be used (a
     * non-URI or relative name, or an unreadable extension), which count as refused by policy.
     */
    record Sources(List<String> ocsp, List<String> crl, int unusable) {

        static Sources of(final X509Certificate cert) {
            final List<String> ocsp = new ArrayList<>();
            final List<String> crl = new ArrayList<>();
            int unusable = 0;
            try {
                final byte[] crlDp = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
                if (crlDp != null) {
                    for (final DistributionPoint dp : CRLDistPoint.getInstance(unwrap(crlDp))
                            .getDistributionPoints()) {
                        final DistributionPointName name = dp.getDistributionPoint();
                        if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                            for (final GeneralName n : GeneralNames.getInstance(name.getName()).getNames()) {
                                if (n.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                    add(crl, n.getName().toString());
                                } else {
                                    unusable++; // directoryName etc.: would need LDAP, never fetched
                                }
                            }
                        } else if (name != null) {
                            unusable++; // relative name
                        }
                    }
                }
                final byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
                if (aia != null) {
                    for (final AccessDescription ad : AuthorityInformationAccess.getInstance(unwrap(aia))
                            .getAccessDescriptions()) {
                        if (AccessDescription.id_ad_ocsp.equals(ad.getAccessMethod())) {
                            if (ad.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                                add(ocsp, ad.getAccessLocation().getName().toString());
                            } else {
                                unusable++;
                            }
                        }
                    }
                }
            } catch (final RuntimeException e) {
                return new Sources(List.of(), List.of(), unusable + 1); // an extension we cannot read
            }
            return new Sources(List.copyOf(ocsp), List.copyOf(crl), unusable);
        }

        private static void add(final List<String> urls, final String url) {
            if (urls.size() < MAX_URLS_PER_KIND && !urls.contains(url)) {
                urls.add(url);
            }
        }
    }
}
