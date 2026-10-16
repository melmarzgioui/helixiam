/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RealmAlgorithmJwtEncoderTest {

    private final JwtEncoder delegate = mock(JwtEncoder.class);
    private final AtomicReference<String> active = new AtomicReference<>("RS256");
    private final RealmAlgorithmJwtEncoder encoder = new RealmAlgorithmJwtEncoder(delegate, active::get);

    private String encodedAlg(final JwsHeader header) {
        final JwtClaimsSet claims = JwtClaimsSet.builder().subject("s").build();
        encoder.encode(header == null ? JwtEncoderParameters.from(claims) : JwtEncoderParameters.from(header, claims));
        final ArgumentCaptor<JwtEncoderParameters> p = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(delegate, org.mockito.Mockito.atLeastOnce()).encode(p.capture());
        final JwsHeader sent = p.getValue().getJwsHeader();
        return sent == null ? null : sent.getAlgorithm().getName();
    }

    @Test
    void anEcRealmSignsEverythingEs256_keepingOtherHeaders() {
        active.set("ES256");
        assertThat(encodedAlg(JwsHeader.with(SignatureAlgorithm.RS256).type("logout+jwt").build())).isEqualTo("ES256");
        assertThat(encodedAlg(JwsHeader.with(SignatureAlgorithm.PS256).build())).isEqualTo("ES256");
        assertThat(encodedAlg(null)).isEqualTo("ES256");
        final ArgumentCaptor<JwtEncoderParameters> p = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(delegate, org.mockito.Mockito.atLeastOnce()).encode(p.capture());
        assertThat(p.getAllValues().get(0).getJwsHeader().getType()).isEqualTo("logout+jwt");
    }

    @Test
    void anRsaRealmKeepsRs256AndPs256_andReplacesEs256() {
        assertThat(encodedAlg(JwsHeader.with(SignatureAlgorithm.PS256).build())).isEqualTo("PS256");
        assertThat(encodedAlg(JwsHeader.with(SignatureAlgorithm.RS256).build())).isEqualTo("RS256");
        assertThat(encodedAlg(JwsHeader.with(SignatureAlgorithm.ES256).build())).isEqualTo("RS256");
        assertThat(encodedAlg(JwsHeader.with(SignatureAlgorithm.RS512).build())).isEqualTo("RS256");
    }

    @Test
    void unknownActiveKey_passesThrough() {
        active.set(null);
        assertThat(encodedAlg(JwsHeader.with(SignatureAlgorithm.ES256).build())).isEqualTo("ES256");
    }
}
