package io.helixiam.authorization.idp.workloadidentity;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Component;

import java.net.URI;
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

    /** A cached JWKS handle for {@code jwksUri} (Nimbus refreshes the key set behind it). */
    public JWKSource<SecurityContext> jwkSource(final String jwksUri) {
        return jwkSourceCache.computeIfAbsent(jwksUri, uri -> {
            try {
                return JWKSourceBuilder.create(URI.create(uri).toURL()).build();
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
