/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class RealmAlgorithmJwtEncoderTest {

    private static final RSAKey RSA = gen(true);
    private static final ECKey EC = genEc();
    private final AtomicReference<String> realmDefault = new AtomicReference<>("RS256");

    private static RSAKey gen(final boolean b) {
        try {
            return new RSAKeyGenerator(2048).keyID("rsa").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ECKey genEc() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("ec").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static JWKSet set(final boolean withEc) throws Exception {
        final List<com.nimbusds.jose.jwk.JWK> keys = new ArrayList<>();
        keys.add(RSA);
        keys.add(new RSAKey.Builder(RSA).keyID("rsa-ps256").algorithm(JWSAlgorithm.PS256).build());
        if (withEc) {
            keys.add(EC);
        }
        return new JWKSet(keys);
    }

    private SignedJWT encode(final JWKSet set, final JwsHeader header) throws Exception {
        final RealmAlgorithmJwtEncoder encoder = new RealmAlgorithmJwtEncoder(() -> set, realmDefault::get,
                mock(JwtEncoder.class));
        final JwtClaimsSet claims = JwtClaimsSet.builder().subject("s").build();
        return SignedJWT.parse(encoder.encode(header == null ? JwtEncoderParameters.from(claims)
                : JwtEncoderParameters.from(header, claims)).getTokenValue());
    }

    @Test
    void explicitAlgorithms_signWithTheMatchingActiveKey() throws Exception {
        final JWKSet both = set(true);
        final SignedJWT es = encode(both, JwsHeader.with(SignatureAlgorithm.ES256).build());
        assertThat(es.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(es.verify(new ECDSAVerifier(EC.toECPublicKey()))).isTrue();
        final SignedJWT rs = encode(both, JwsHeader.with(SignatureAlgorithm.RS256).build());
        assertThat(rs.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(rs.verify(new RSASSAVerifier(RSA.toRSAPublicKey()))).isTrue();
        assertThat(encode(both, JwsHeader.with(SignatureAlgorithm.PS256).build()).getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.PS256);
    }

    @Test
    void anAlgorithmWithoutActiveKey_fallsBackToRs256() throws Exception {
        assertThat(encode(set(false), JwsHeader.with(SignatureAlgorithm.ES256).build()).getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.RS256);
        assertThat(encode(set(false), JwsHeader.with(SignatureAlgorithm.RS512).build()).getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void realmDefault_followsTheRealmSetting_keepingOtherHeaders() throws Exception {
        realmDefault.set("ES256");
        final SignedJWT t = encode(set(true), JwsHeader.with(RealmAlgorithmJwtEncoder.REALM_DEFAULT).type("logout+jwt").build());
        assertThat(t.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(t.getHeader().getType().toString()).isEqualTo("logout+jwt");
        realmDefault.set(null);
        assertThat(encode(set(true), JwsHeader.with(RealmAlgorithmJwtEncoder.REALM_DEFAULT).build()).getHeader()
                .getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        realmDefault.set("ES256");
        assertThat(encode(set(false), JwsHeader.with(RealmAlgorithmJwtEncoder.REALM_DEFAULT).build()).getHeader()
                .getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(encode(set(true), null).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void theKeySetIsReadOncePerEncode() throws Exception {
        final AtomicInteger calls = new AtomicInteger();
        final JWKSet set = set(true);
        final RealmAlgorithmJwtEncoder encoder = new RealmAlgorithmJwtEncoder(() -> {
            calls.incrementAndGet();
            return set;
        }, realmDefault::get, mock(JwtEncoder.class));
        encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES256).build(),
                JwtClaimsSet.builder().subject("s").build()));
        assertThat(calls.get()).isEqualTo(1);
    }
}
