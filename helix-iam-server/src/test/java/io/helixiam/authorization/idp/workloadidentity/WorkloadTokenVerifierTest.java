package io.helixiam.authorization.idp.workloadidentity;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM WIF: the verifier is the security gate — a workload token is trusted only if its signature
 * checks against the issuer's published keys AND its issuer/audience/subject exactly match the
 * registered credential. These tests sign real RS256 JWTs against an in-memory JWKS and assert each
 * failure mode rejects.
 */
class WorkloadTokenVerifierTest {

    private static final String ISSUER = "https://kubernetes.default.svc.cluster.local";
    private static final String SUBJECT = "system:serviceaccount:apps:billing";
    private static final String AUDIENCE = "helix";

    private RSAKey signingKey;
    private JWKSource<SecurityContext> jwkSource;
    private WorkloadTokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("k8s-1").generate();
        jwkSource = new ImmutableJWKSet<>(new JWKSet(signingKey.toPublicJWK()));
        verifier = new WorkloadTokenVerifier();
    }

    private String token(final String issuer, final String subject, final List<String> audience,
                         final Date expiry) throws Exception {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer).subject(subject).audience(audience)
                .issueTime(new Date()).expirationTime(expiry).build();
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }

    private Date inOneHour() {
        return new Date(System.currentTimeMillis() + 3_600_000);
    }

    @Test
    void acceptsAValidlySignedMatchingToken() throws Exception {
        final String jwt = token(ISSUER, SUBJECT, List.of(AUDIENCE), inOneHour());

        final JWTClaimsSet claims = verifier.verify(jwkSource, ISSUER, AUDIENCE, SUBJECT, jwt);

        assertThat(claims.getSubject()).isEqualTo(SUBJECT);
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    void rejectsATokenSignedByAnUnknownKey() throws Exception {
        final RSAKey attacker = new RSAKeyGenerator(2048).keyID("attacker").generate();
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER).subject(SUBJECT).audience(AUDIENCE).expirationTime(inOneHour()).build();
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("attacker").build(), claims);
        jwt.sign(new RSASSASigner(attacker));

        assertThatThrownBy(() -> verifier.verify(jwkSource, ISSUER, AUDIENCE, SUBJECT, jwt.serialize()))
                .isInstanceOf(Exception.class);
    }

    @Test
    void rejectsAWrongIssuer() throws Exception {
        final String jwt = token("https://evil.example.com", SUBJECT, List.of(AUDIENCE), inOneHour());

        assertThatThrownBy(() -> verifier.verify(jwkSource, ISSUER, AUDIENCE, SUBJECT, jwt))
                .isInstanceOf(Exception.class);
    }

    @Test
    void rejectsAWrongAudience() throws Exception {
        final String jwt = token(ISSUER, SUBJECT, List.of("some-other-aud"), inOneHour());

        assertThatThrownBy(() -> verifier.verify(jwkSource, ISSUER, AUDIENCE, SUBJECT, jwt))
                .isInstanceOf(Exception.class);
    }

    @Test
    void rejectsAWrongSubject() throws Exception {
        final String jwt = token(ISSUER, "system:serviceaccount:apps:attacker", List.of(AUDIENCE), inOneHour());

        assertThatThrownBy(() -> verifier.verify(jwkSource, ISSUER, AUDIENCE, SUBJECT, jwt))
                .isInstanceOf(Exception.class);
    }

    @Test
    void rejectsAnExpiredToken() throws Exception {
        final String jwt = token(ISSUER, SUBJECT, List.of(AUDIENCE), new Date(System.currentTimeMillis() - 60_000));

        assertThatThrownBy(() -> verifier.verify(jwkSource, ISSUER, AUDIENCE, SUBJECT, jwt))
                .isInstanceOf(Exception.class);
    }
}
