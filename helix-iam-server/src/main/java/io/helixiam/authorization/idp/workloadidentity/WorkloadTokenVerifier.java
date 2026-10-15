/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.workloadidentity;

import io.helixiam.common.json.JsonMappers;
import io.helixiam.common.json.JsonNodes;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;
import io.helixiam.common.net.PinnedResourceRetriever;
import io.helixiam.common.net.SsrfBlockedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Helix IAM WIF: the cryptographic gate of the token exchange. A presented workload JWT is trusted only
 * after {@link #verify} confirms, in one pass:
 * <ul>
 *   <li>the signature validates against the issuer's published JWKS (RS256/ES256 only — no {@code none},
 *       no symmetric algorithms);</li>
 *   <li>{@code iss} exactly equals the credential's registered issuer;</li>
 *   <li>{@code aud} contains the credential's registered audience;</li>
 *   <li>{@code sub} exactly equals the credential's registered subject;</li>
 *   <li>{@code exp} is in the future (Nimbus default skew).</li>
 * </ul>
 * The expected values come from the stored credential, NOT the token's self-asserted claims, so a forged
 * or mis-targeted token can never select a credential it doesn't cryptographically satisfy. JWKS sources
 * are cached per URL (Nimbus handles key-set refresh + rotation behind that handle).
 */
@Component
public class WorkloadTokenVerifier {

    /** Only asymmetric signatures are accepted; this set excludes {@code none} and HMAC by construction. */
    private static final Set<JWSAlgorithm> ALLOWED_ALGS = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384,
            JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512, JWSAlgorithm.PS256);

    private final ConcurrentHashMap<String, JWKSource<SecurityContext>> jwkSourceCache = new ConcurrentHashMap<>();
    private final OutboundUrlGuard egressGuard;
    private final PinnedHttpFetcher http;
    private final PinnedResourceRetriever jwksRetriever;
    private static final PinnedHttpFetcher.Limits DISCOVERY_LIMITS = new PinnedHttpFetcher.Limits(
            Duration.ofSeconds(5), Duration.ofSeconds(5), 1024 * 1024);
    private static final ObjectMapper MAPPER = JsonMappers.plain();

    /** Secure default (block-private) for non-Spring construction (tests that build their own JWKSource). */
    public WorkloadTokenVerifier() {
        this(new OutboundUrlGuard());
    }

    @Autowired
    public WorkloadTokenVerifier(final OutboundUrlGuard egressGuard) {
        this.egressGuard = egressGuard;
        this.http = PinnedHttpFetcher.plain(egressGuard,
                io.helixiam.common.net.FetchLimiter.Group.LOGIN_ADMIN, io.helixiam.authorization.security.realm.RealmContextHolder::get);
        this.jwksRetriever = new PinnedResourceRetriever(egressGuard,
                io.helixiam.common.net.FetchLimiter.Group.LOGIN_ADMIN, io.helixiam.authorization.security.realm.RealmContextHolder::get);
    }

    /** M6: rejects an issuer-discovery URL (derived from the admin-configured WIF issuer) the egress policy forbids. */
    public void checkEgress(final String url) throws SsrfBlockedException {
        egressGuard.checkAllowed(url);
    }

    /**
     * GETs the issuer's discovery document at {@code url} (M6: through the guard, pinned to the validated address, no
     * redirects, 5 s in total, at most 1 MB) and returns its {@code jwks_uri}.
     *
     * @throws SsrfBlockedException the guard refused the URL
     * @throws IllegalStateException a status other than 200, or no {@code jwks_uri}
     */
    public String discoverJwksUri(final String url) throws Exception {
        final PinnedHttpFetcher.Response resp = http.get(url, Map.of("Accept", "application/json"), DISCOVERY_LIMITS);
        if (resp.status() != 200) {
            throw new IllegalStateException("issuer discovery returned " + resp.status());
        }
        final JsonNode jwks = MAPPER.readTree(resp.bodyAsString()).path("jwks_uri");
        if (jwks.isMissingNode() || JsonNodes.text(jwks).isBlank()) {
            throw new IllegalStateException("issuer discovery has no jwks_uri");
        }
        return JsonNodes.text(jwks);
    }

    /** A cached JWKS handle for {@code jwksUri} (Nimbus refreshes the key set behind it). */
    public JWKSource<SecurityContext> jwkSource(final String jwksUri) {
        return jwkSourceCache.computeIfAbsent(jwksUri, uri -> {
            try {
                egressGuard.checkAllowed(uri); // M6: jwksUri comes from the admin/DCR-registered WIF credential
                // ...and every fetch behind the handle is pinned to the address the guard validates then
                return JWKSourceBuilder.create(URI.create(uri).toURL(), jwksRetriever).build();
            } catch (final SsrfBlockedException e) {
                throw new IllegalStateException("Blocked JWKS URI (SSRF guard): " + uri, e);
            } catch (final Exception e) {
                throw new IllegalStateException("Invalid JWKS URI: " + uri, e);
            }
        });
    }

    /**
     * Verify {@code token} against {@code jwkSource} and the credential's expected issuer/audience/subject,
     * returning the verified claims. Throws when any check fails (the caller maps every failure to one
     * generic 401 — no enumeration of which check failed).
     */
    public JWTClaimsSet verify(final JWKSource<SecurityContext> jwkSource, final String expectedIssuer,
                               final String expectedAudience, final String expectedSubject,
                               final String token) throws Exception {
        final ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ALLOWED_ALGS, jwkSource));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                expectedAudience,
                new JWTClaimsSet.Builder().issuer(expectedIssuer).subject(expectedSubject).build(),
                Set.of("iss", "sub", "aud", "exp")));
        return processor.process(token, null);
    }
}
