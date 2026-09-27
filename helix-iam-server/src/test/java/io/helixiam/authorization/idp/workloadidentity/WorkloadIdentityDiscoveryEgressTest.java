/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.workloadidentity;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityCredentialDto;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.net.OutboundUrlGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * SSRF (M6): with no explicit {@code jwksUri}, the WIF exchange discovers it from the credential's
 * admin-configured issuer — a server-side GET an unauthenticated caller can trigger (the subject_token's
 * iss/sub/aud are read unverified to pick the credential). That discovery GET must pass the egress guard,
 * like the JWKS fetch it leads to, so an issuer on an internal address is never contacted.
 */
class WorkloadIdentityDiscoveryEgressTest {

    private HttpServer internal;

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
        if (internal != null) {
            internal.stop(0);
        }
    }

    @Test
    void issuerDiscovery_onAnInternalAddress_isNeverFetched() throws Exception {
        final AtomicInteger hits = new AtomicInteger();
        internal = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        internal.createContext("/", exchange -> {
            hits.incrementAndGet();
            final byte[] body = "{\"jwks_uri\":\"http://127.0.0.1/jwks\"}".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        internal.start();
        final String issuer = "http://127.0.0.1:" + internal.getAddress().getPort();

        final WorkloadIdentityConfigPublisher credentials = mock(WorkloadIdentityConfigPublisher.class);
        when(credentials.resolve(any())).thenReturn(new WorkloadIdentityCredentialDto("c1", "wif", "ci", issuer,
                null, "system:serviceaccount:ns:app", "helix", "ci-client", null, true, 0L));
        final WorkloadIdentityTokenController controller = new WorkloadIdentityTokenController(credentials,
                new WorkloadTokenVerifier(OutboundUrlGuard.blocking()), null, null, null,
                AuthorizationServerSettings.builder().build(), mock(AuditLog.class), 900);
        RealmContextHolder.set("wif");

        final SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder()
                .issuer(issuer).subject("system:serviceaccount:ns:app").audience(List.of("helix"))
                .expirationTime(new Date(System.currentTimeMillis() + 60_000)).build());
        jwt.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));

        final ResponseEntity<?> res = controller.exchange("urn:ietf:params:oauth:grant-type:token-exchange",
                jwt.serialize(), null, new MockHttpServletRequest());

        assertThat(res.getStatusCode().value()).isEqualTo(401);
        assertThat(hits.get()).as("the internal issuer's discovery document must not be requested").isZero();
    }
}
