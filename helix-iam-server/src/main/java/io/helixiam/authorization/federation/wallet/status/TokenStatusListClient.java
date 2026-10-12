/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.SsrfBlockedException;
import io.helixiam.common.net.UnresolvableHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.TrustAnchor;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

/**
 * Resolves a credential's Token Status List reference (draft-ietf-oauth-status-list-21 §8) for one wallet provider,
 * under that provider's {@link StatusPolicy}.
 *
 * <p><b>Retrieval.</b> The {@code uri} (and every redirect target, at most {@value #MAX_REDIRECTS}) must be
 * {@code https}, match {@link StatusPolicy#allowedHosts()} when that list is non-empty (exact host name,
 * case-insensitive), and pass {@link OutboundUrlGuard#checkAllowed} (private / loopback / link-local / metadata
 * addresses refused) <em>before</em> any connection is opened. Redirects are followed by hand so each hop is vetted.
 * One GET with {@code Accept: application/statuslist+jwt} ({@code +cwt} for {@link #cwtEvaluator()}); connect timeout
 * {@value #CONNECT_TIMEOUT_SECONDS} s; the response, headers and body together, must arrive within
 * {@value #READ_TIMEOUT_SECONDS} s; the body is capped at {@value #MAX_BODY_BYTES} bytes ({@code LIMIT_EXCEEDED}).
 * The response {@code Content-Type} is not trusted: the signed {@code typ} / COSE type decides.
 *
 * <p><b>Validation.</b> {@link StatusListToken} verifies the signature with the {@code x5c} / {@code x5chain} chain
 * against the <em>same</em> {@link TrustAnchors} as the credential, {@code iat}, {@code bits} and the inflated size
 * ({@value StatusListToken#MAX_INFLATED_BYTES} bytes); here {@code sub} must equal the referenced {@code uri} and an
 * {@code exp} must not have passed.
 *
 * <p><b>Cache.</b> Verified tokens are cached by {@code uri} and form, for the anchors they were verified against, until
 * {@code min(ttl, maxCache)} after retrieval (without {@code ttl}: {@code maxCache}), and never past {@code exp}.
 * Failures are not cached.
 *
 * <p><b>Outcome.</b> Status {@code 0} returns {@link StatusEvaluator#VALID}; {@code 1} (INVALID) throws
 * {@code CREDENTIAL_REVOKED}; {@code 2} throws {@code CREDENTIAL_SUSPENDED}; every other value (application-specific
 * {@code 3}, {@code 0x0C-0x0F}, reserved) is not VALID and throws {@code CREDENTIAL_REVOKED}. An index outside a valid
 * list is {@code INVALID_RESPONSE} (§8.3 step 6: the token "MUST be rejected"). These definite answers are never
 * subject to the unavailability policy.
 *
 * <p><b>Fail closed vs. fail open.</b> Only a <em>transient availability failure</em> is subject to
 * {@link StatusPolicy#onUnavailable()}: a connect or read error, a timeout, an HTTP 5xx answer, or a host name that
 * cannot be resolved ({@link UnresolvableHostException} from the guard). These are raised as the private
 * {@link TransientFailure} type, so the classification is structural, never by message text. Under {@code FAIL_CLOSED}
 * they throw {@code STATUS_UNAVAILABLE}; under {@code FAIL_OPEN_WITH_AUDIT} they are logged, recorded through the
 * {@link AuditSink} and answered {@code VALID} (if the audit cannot be recorded, it fails closed).
 *
 * <p>Everything else <b>always fails closed</b>, under both policies: policy refusals (a non-https uri or redirect
 * hop, a host the guard blocks, a host outside {@code allowedHosts}), every integrity failure of the fetched list (bad
 * signature, untrusted / expired chain, wrong {@code typ} / type, alg not allowed, {@code sub} not equal to the uri),
 * and any other non-transient failure (non-5xx error status, too many redirects, malformed list, expired token). These
 * throw {@code STATUS_UNAVAILABLE}, or {@code LIMIT_EXCEEDED} for a size limit (body, inflated list).
 *
 * <p>This class is the single place that applies {@code onUnavailable} to a status-list evaluation: it never lets a
 * non-wallet exception escape, so the verifiers' own unavailability path (for a status claim without an evaluable
 * mechanism) is never reached for a status list.
 */
public final class TokenStatusListClient implements StatusEvaluator {

    public static final int CONNECT_TIMEOUT_SECONDS = 3;
    public static final int READ_TIMEOUT_SECONDS = 5;
    public static final int MAX_BODY_BYTES = 1024 * 1024;
    public static final int MAX_REDIRECTS = 3;
    /** {@code maxCache} when the policy leaves it unset, and its upper bound (spec: status cache max 900 s). */
    public static final Duration DEFAULT_MAX_CACHE = Duration.ofSeconds(900);
    /** Most status lists kept; each may hold up to 2 MB inflated. */
    static final int MAX_CACHE_ENTRIES = 64;

    private static final Logger LOG = LogManager.getLogger(TokenStatusListClient.class);
    private static final String JWT_MEDIA_TYPE = "application/statuslist+jwt";
    private static final String CWT_MEDIA_TYPE = "application/statuslist+cwt";
    /** Body reads run here so a stalled body can be abandoned at the deadline. */
    private static final ExecutorService BODY_READERS = Executors.newThreadPerTaskExecutor(
            Thread.ofVirtual().name("status-list-read-", 0).factory());

    /** Records an unavailable status accepted under {@code FAIL_OPEN_WITH_AUDIT}. Must not throw on success. */
    @FunctionalInterface
    public interface AuditSink {
        /**
         * @param statusListHost the status list's host (never the full URI)
         * @param code           {@code STATUS_UNAVAILABLE} or {@code LIMIT_EXCEEDED}
         * @param safeDetail     a safe reason
         */
        void statusUnavailableAccepted(String statusListHost, WalletErrorCode code, String safeDetail);
    }

    /**
     * A transient availability failure (connect / read error, timeout, HTTP 5xx, DNS resolution failure): the only
     * failure {@code onUnavailable} may turn into {@code VALID}. Never escapes this class.
     */
    private static final class TransientFailure extends RuntimeException {
        TransientFailure(final String safeDetail) {
            super(safeDetail, null, false, false);
        }
    }

    /** The two Status List Token forms. */
    private enum Form { JWT, CWT }

    private record CacheKey(String uri, Form form) {
    }

    private record CacheEntry(StatusListToken token, Set<Object> anchors, Instant until) {
    }

    private final StatusPolicy policy;
    private final IssuerTrustValidator trust;
    private final OutboundUrlGuard guard;
    private final Clock clock;
    private final AuditSink audit;
    private final HttpClient http;
    private final Duration maxCache;
    private final Set<String> allowedHosts;
    private final Map<CacheKey, CacheEntry> cache = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(final Map.Entry<CacheKey, CacheEntry> eldest) {
            return size() > MAX_CACHE_ENTRIES;
        }
    };

    /** Production wiring: the JDK default trust store and the system clock. */
    public TokenStatusListClient(final StatusPolicy policy, final IssuerTrustValidator trust,
            final OutboundUrlGuard guard, final AuditSink audit) {
        this(policy, trust, guard, defaultSslContext(), Clock.systemUTC(), audit);
    }

    public TokenStatusListClient(final StatusPolicy policy, final IssuerTrustValidator trust,
            final OutboundUrlGuard guard, final SSLContext sslContext, final Clock clock, final AuditSink audit) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.trust = Objects.requireNonNull(trust, "trust");
        this.guard = Objects.requireNonNull(guard, "guard");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = Objects.requireNonNull(audit, "audit");
        Objects.requireNonNull(policy.onUnavailable(), "policy.onUnavailable");
        final Duration configured = policy.maxCache();
        if (configured != null && configured.isNegative()) {
            throw new IllegalArgumentException("statusList.maxCache must not be negative");
        }
        this.maxCache = configured == null || configured.compareTo(DEFAULT_MAX_CACHE) > 0 ? DEFAULT_MAX_CACHE
                : configured;
        this.allowedHosts = policy.allowedHosts() == null ? Set.of() : policy.allowedHosts().stream()
                .filter(Objects::nonNull).map(h -> h.trim().toLowerCase(Locale.ROOT)).filter(h -> !h.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(Objects.requireNonNull(sslContext, "sslContext"))
                .build();
    }

    /** The connect timeout of the underlying HTTP client. */
    Duration connectTimeout() {
        return http.connectTimeout().orElseThrow();
    }

    /** An {@link AuditSink} that emits {@code WALLET_STATUS_CHECK_FAILED} (AUTHN) for the current realm. */
    public static AuditSink auditLogSink(final AuditLog auditLog) {
        Objects.requireNonNull(auditLog, "auditLog");
        return (host, code, detail) -> auditLog.emit(AuditEvent.authn(AuditContext.nowIso(),
                "WALLET_STATUS_CHECK_FAILED", RealmContextHolder.get(), AuditContext.ANONYMOUS, null, "FAILURE",
                Map.of("reason", code.reason(), "statusListHost", LogSafe.sanitize(host),
                        "decision", StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT.name())));
    }

    /** The policy this client enforces (the provider's, the same instance as in its verification context). */
    public StatusPolicy policy() {
        return policy;
    }

    /**
     * Evaluates a reference to a Status List Token in JWT form (SD-JWT VC: "MUST be in JWT format"). The Token Status
     * List draft and SD-JWT VC define no rule binding a JWT list's signer to the credential issuer (the list must chain
     * to the same anchors), so this form needs no issuer.
     */
    public String evaluate(final StatusReference ref, final TrustAnchors anchors) {
        return evaluate(ref, anchors, Form.JWT, null);
    }

    /** JWT form, as the presentation verifiers call it; {@code issuer} is required but has no rule to apply here. */
    @Override
    public String evaluate(final StatusReference ref, final TrustAnchors anchors, final CredentialIssuer issuer) {
        Objects.requireNonNull(issuer, "issuer");
        return evaluate(ref, anchors, Form.JWT, null);
    }

    /**
     * The same client for Status List Tokens in CWT form ({@code application/statuslist+cwt}, ISO mdoc). It always
     * enforces the ISO §12.3.6 signer rule ({@link MdocStatusListSigner}) on the PKIX-validated chains, on every
     * evaluation including cache hits; that refusal always fails closed. There is no CWT form without the issuer.
     */
    public StatusEvaluator cwtEvaluator() {
        return (ref, anchors, issuer) -> evaluate(ref, anchors, Form.CWT, Objects.requireNonNull(issuer, "issuer"));
    }

    private String evaluate(final StatusReference ref, final TrustAnchors anchors, final Form form,
            final CredentialIssuer issuer) {
        Objects.requireNonNull(ref, "ref");
        Objects.requireNonNull(anchors, "anchors");
        final StatusListToken token;
        try {
            token = load(ref.uri(), anchors, form);
            if (issuer != null) {
                MdocStatusListSigner.check(token.signer(), issuer);
            }
        } catch (final TransientFailure e) {
            return unavailable(ref.uri(), e.getMessage());
        } catch (final WalletVerificationException e) {
            // policy refusal, integrity failure or other non-transient failure: never fail-open
            throw refused(ref.uri(), e.code() == WalletErrorCode.LIMIT_EXCEEDED
                    ? WalletErrorCode.LIMIT_EXCEEDED : WalletErrorCode.STATUS_UNAVAILABLE, e.getMessage());
        } catch (final RuntimeException e) {
            throw refused(ref.uri(), WalletErrorCode.STATUS_UNAVAILABLE, "status list could not be evaluated");
        }
        final int status = token.statusAt(ref.idx()); // out of range: INVALID_RESPONSE, a definite rejection
        return switch (status) {
            case 0 -> VALID;
            case 2 -> throw new WalletVerificationException(WalletErrorCode.CREDENTIAL_SUSPENDED,
                    "credential is suspended");
            default -> throw new WalletVerificationException(WalletErrorCode.CREDENTIAL_REVOKED,
                    status == 1 ? "credential is revoked" : "credential status is not VALID");
        };
    }

    /** A failure that is never subject to {@code onUnavailable}. */
    private static WalletVerificationException refused(final String uri, final WalletErrorCode code,
            final String safeDetail) {
        LOG.info("Credential status list refused: host={} code={} detail={}", LogSafe.sanitize(hostOf(uri)), code,
                safeDetail);
        return new WalletVerificationException(code, safeDetail);
    }

    /** The one place {@code onUnavailable} is applied: transient availability failures only. */
    private String unavailable(final String uri, final String safeDetail) {
        final WalletErrorCode code = WalletErrorCode.STATUS_UNAVAILABLE;
        final String host = LogSafe.sanitize(hostOf(uri));
        if (policy.onUnavailable() != StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT) {
            LOG.debug("Credential status unavailable: host={} code={} detail={}", host, code, safeDetail);
            throw new WalletVerificationException(code, safeDetail);
        }
        try {
            audit.statusUnavailableAccepted(host, code, safeDetail);
        } catch (final RuntimeException e) {
            // "with audit": no record, no fail-open
            LOG.warn("Credential status unavailable and the audit could not be recorded; refusing: host={} code={}",
                    host, code);
            throw new WalletVerificationException(code, safeDetail);
        }
        LOG.warn("Credential status unavailable, accepted under FAIL_OPEN_WITH_AUDIT: host={} code={} detail={}",
                host, code, safeDetail);
        return VALID;
    }

    // ------------------------------------------------------------------------------------------- cache + validation

    private StatusListToken load(final String uri, final TrustAnchors anchors, final Form form) {
        final CacheKey key = new CacheKey(uri, form);
        final Set<Object> anchorIds = anchorIds(anchors);
        final Instant now = clock.instant();
        final CacheEntry cached;
        synchronized (cache) {
            cached = cache.get(key);
        }
        if (cached != null && cached.anchors().equals(anchorIds) && now.isBefore(cached.until())
                && !cached.token().isExpiredAt(now)) {
            return cached.token();
        }

        final byte[] body = fetch(uri, form);
        final StatusListToken token = form == Form.JWT
                ? StatusListToken.fromJwt(new String(body, StandardCharsets.UTF_8), anchors, now, trust)
                : StatusListToken.fromCwt(body, anchors, now, trust);
        if (!uri.equals(token.subject())) {
            throw nonTransient("Status List Token sub does not match the status list uri");
        }
        if (token.isExpiredAt(now)) {
            throw nonTransient("Status List Token is expired");
        }
        final Duration ttl = token.ttl() == null || token.ttl().compareTo(maxCache) > 0 ? maxCache : token.ttl();
        Instant until = now.plus(ttl);
        if (token.expiresAt() != null && token.expiresAt().isBefore(until)) {
            until = token.expiresAt();
        }
        synchronized (cache) {
            cache.put(key, new CacheEntry(token, anchorIds, until));
        }
        return token;
    }

    /** What makes two {@link TrustAnchors} the same for caching: their certificates / keys and revocation mode. */
    private static Set<Object> anchorIds(final TrustAnchors anchors) {
        final Set<Object> ids = new java.util.HashSet<>();
        for (final TrustAnchor a : anchors.anchors()) {
            ids.add(a.getTrustedCert() != null ? a.getTrustedCert() : a.getCAPublicKey());
        }
        ids.add(List.copyOf(anchors.pinnedIntermediates()));
        ids.add(anchors.revocation());
        return Set.copyOf(ids);
    }

    // ------------------------------------------------------------------------------------------- retrieval

    private byte[] fetch(final String uri, final Form form) {
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(READ_TIMEOUT_SECONDS);
        URI target = vet(uri);
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            final HttpResponse<InputStream> response = send(target, form, deadline);
            final int status = response.statusCode();
            if (status / 100 == 3) {
                close(response.body());
                final String location = response.headers().firstValue("Location").orElse(null);
                if (location == null) {
                    throw nonTransient("status list redirect has no location");
                }
                try {
                    target = vet(target.resolve(location).toString());
                } catch (final IllegalArgumentException e) {
                    throw nonTransient("status list redirect location is malformed");
                }
                continue;
            }
            if (status != 200) {
                close(response.body());
                if (status / 100 == 5) {
                    throw new TransientFailure("status list server answered HTTP " + status);
                }
                throw nonTransient("status list server answered HTTP " + status);
            }
            return readBody(response.body(), deadline);
        }
        throw nonTransient("status list redirected too often");
    }

    /** {@code https}, allowed host, and the outbound guard, before any connection; returns the parsed URI. */
    private URI vet(final String uri) {
        final URI parsed;
        try {
            parsed = new URI(uri);
        } catch (final URISyntaxException | NullPointerException e) {
            throw nonTransient("status list uri is malformed");
        }
        if (!"https".equalsIgnoreCase(parsed.getScheme())) {
            throw nonTransient("status list uri is not https");
        }
        if (parsed.getHost() == null || parsed.getRawUserInfo() != null) {
            throw nonTransient("status list uri has no plain host");
        }
        if (!allowedHosts.isEmpty() && !allowedHosts.contains(bareHost(parsed.getHost()))) {
            throw nonTransient("status list host is not in allowedHosts");
        }
        try {
            guard.checkAllowed(parsed.toString());
        } catch (final UnresolvableHostException e) {
            throw new TransientFailure("status list host could not be resolved");
        } catch (final SsrfBlockedException e) {
            throw nonTransient("status list host is not allowed");
        }
        return parsed;
    }

    private HttpResponse<InputStream> send(final URI target, final Form form, final long deadline) {
        final long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new TransientFailure("status list request timed out");
        }
        final HttpRequest request = HttpRequest.newBuilder(target)
                .timeout(Duration.ofNanos(remaining))
                .header("Accept", form == Form.JWT ? JWT_MEDIA_TYPE : CWT_MEDIA_TYPE)
                .GET()
                .build();
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (final java.net.http.HttpTimeoutException e) {
            throw new TransientFailure("status list request timed out");
        } catch (final IOException e) {
            throw new TransientFailure("status list could not be fetched");
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransientFailure("status list fetch was interrupted");
        }
    }

    /** Reads at most {@link #MAX_BODY_BYTES} before {@code deadline}; a stalled body is abandoned and closed. */
    private static byte[] readBody(final InputStream in, final long deadline) {
        final CompletableFuture<byte[]> read = CompletableFuture.supplyAsync(() -> {
            try (in) {
                return in.readNBytes(MAX_BODY_BYTES + 1);
            } catch (final IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }, BODY_READERS);
        final byte[] body;
        try {
            body = read.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (final TimeoutException e) {
            read.cancel(true);
            close(in);
            throw new TransientFailure("status list response timed out");
        } catch (final ExecutionException e) {
            throw new TransientFailure("status list could not be read");
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            close(in);
            throw new TransientFailure("status list fetch was interrupted");
        }
        if (body.length > MAX_BODY_BYTES) {
            throw new WalletVerificationException(WalletErrorCode.LIMIT_EXCEEDED,
                    "status list response exceeds " + MAX_BODY_BYTES + " bytes");
        }
        return body;
    }

    private static void close(final InputStream in) {
        try {
            in.close();
        } catch (final IOException e) {
            // nothing to do: the response is abandoned
        }
    }

    private static String bareHost(final String host) {
        final String h = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        return h.toLowerCase(Locale.ROOT);
    }

    private static String hostOf(final String uri) {
        try {
            final String host = new URI(uri).getHost();
            return host == null ? "(none)" : bareHost(host);
        } catch (final URISyntaxException | NullPointerException e) {
            return "(unparseable)";
        }
    }

    /** A non-transient failure: always fails closed (see the class comment). */
    private static WalletVerificationException nonTransient(final String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.STATUS_UNAVAILABLE, safeDetail);
    }

    private static SSLContext defaultSslContext() {
        try {
            return SSLContext.getDefault();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("No default TLS context", e);
        }
    }
}
