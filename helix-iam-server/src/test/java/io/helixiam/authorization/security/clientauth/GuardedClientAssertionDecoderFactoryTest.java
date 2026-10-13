/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.clientauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * private_key_jwt: the client's registered JWKS ({@code jwk_set_url}) is attacker-chosen (any client registrant,
 * open DCR included). SAS's own client-assertion decoder fetched it through an unguarded RestTemplate that followed
 * redirects; this factory fetches it through the outbound guard on the pinned transport, without redirects.
 */
class GuardedClientAssertionDecoderFactoryTest {

    private static final String TOKEN_ENDPOINT = "https://idp.test/realms/r/oauth2/token";
    private static RSAKey key;

    @BeforeAll
    static void keys() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("k1").generate();
    }

    @org.junit.jupiter.api.BeforeEach
    void issuer() {
        final org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings settings =
                org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings.builder()
                        .build();
        org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder.setContext(
                new org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext() {
                    @Override
                    public String getIssuer() {
                        return "https://idp.test/realms/r";
                    }

                    @Override
                    public org.springframework.security.oauth2.server.authorization.settings
                            .AuthorizationServerSettings getAuthorizationServerSettings() {
                        return settings;
                    }
                });
    }

    @org.junit.jupiter.api.AfterEach
    void clear() {
        org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
                .resetContext();
    }

    private static RegisteredClient client(final String jwkSetUrl) {
        return RegisteredClient.withId(UUID.randomUUID().toString()).clientId("c1")
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder().jwkSetUrl(jwkSetUrl)
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256).build())
                .build();
    }

    private static String assertion(final RSAKey signer) throws Exception {
        final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signer.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer("c1").subject("c1").audience(TOKEN_ENDPOINT)
                        .jwtID(UUID.randomUUID().toString()).issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 60_000)).build());
        jwt.sign(new RSASSASigner(signer));
        return jwt.serialize();
    }

    @Test
    void aValidAssertionIsVerifiedAgainstTheJwksFetchedFromTheValidatedAddress() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("jwks.client.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/json",
                    new JWKSet(key.toPublicJWK()).toString()));
            final GuardedClientAssertionDecoderFactory factory = new GuardedClientAssertionDecoderFactory(
                    target.guard());

            final Jwt jwt = factory.createDecoder(client(target.url("http", "/jwks"))).decode(assertion(key));

            assertThat(jwt.getSubject()).isEqualTo("c1");
            assertThat(target.requests()).hasSize(1);
            assertThat(target.lookups()).isEqualTo(1);
        }
    }

    @Test
    void aJwksUrlOnTheMetadataAddressIsNeverFetched() {
        final GuardedClientAssertionDecoderFactory factory = new GuardedClientAssertionDecoderFactory(
                OutboundUrlGuard.blocking());
        assertThatThrownBy(() -> factory.createDecoder(client("http://169.254.169.254/latest/meta-data/jwks"))
                .decode(assertion(key))).isInstanceOf(JwtException.class);
    }

    @Test
    @SuppressWarnings("try")
    void aJwksHostThatRebindsToTheMetadataAddressIsRefusedBeforeConnecting() {
        try (RebindingTarget target = RebindingTarget.http("jwks.client.test")) {
            final GuardedClientAssertionDecoderFactory factory = new GuardedClientAssertionDecoderFactory(
                    target.guard(0)); // every answer is the metadata address
            assertThatThrownBy(() -> factory.createDecoder(client(target.url("http", "/jwks"))).decode(assertion(key)))
                    .isInstanceOf(JwtException.class);
            assertThat(target.requests()).isEmpty();
        }
    }

    @Test
    void aRedirectIsNotFollowed() throws Exception {
        try (ServerSocket counting = new ServerSocket(0); RebindingTarget target = RebindingTarget.http("jwks.client.test")) {
            final AtomicInteger hits = new AtomicInteger();
            final Thread t = new Thread(() -> {
                while (!counting.isClosed()) {
                    try (Socket s = counting.accept()) {
                        hits.incrementAndGet();
                    } catch (final java.io.IOException e) {
                        return;
                    }
                }
            });
            t.setDaemon(true);
            t.start();
            target.respond(s -> new RebindingTarget.Answer(302, null, null,
                    Map.of("Location", "http://127.0.0.1:" + counting.getLocalPort() + "/jwks")));
            final GuardedClientAssertionDecoderFactory factory = new GuardedClientAssertionDecoderFactory(
                    target.guard());

            assertThatThrownBy(() -> factory.createDecoder(client(target.url("http", "/jwks"))).decode(assertion(key)))
                    .isInstanceOf(JwtException.class);
            Thread.sleep(200);
            assertThat(hits).hasValue(0);
            assertThat(target.requests()).hasSize(1);
        }
    }

    @Test
    void aRotatedKeyIsPickedUpOnAnUnknownKid() throws Exception {
        final RSAKey rotated = new RSAKeyGenerator(2048).keyID("k2").generate();
        try (RebindingTarget target = RebindingTarget.http("jwks.client.test")) {
            final java.util.concurrent.atomic.AtomicReference<JWKSet> served =
                    new java.util.concurrent.atomic.AtomicReference<>(new JWKSet(key.toPublicJWK()));
            target.respond(s -> new RebindingTarget.Answer(200, "application/json", served.get().toString()));
            final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("jwks.client.test:" + target.port()),
                    host -> new java.net.InetAddress[] {java.net.InetAddress.getByAddress(host,
                            new byte[] {127, 0, 0, 1})});
            final GuardedClientAssertionDecoderFactory factory = new GuardedClientAssertionDecoderFactory(guard);
            final RegisteredClient c = client(target.url("http", "/jwks"));

            factory.createDecoder(c).decode(assertion(key));
            factory.createDecoder(c).decode(assertion(key));
            assertThat(target.requests()).hasSize(1); // cached

            served.set(new JWKSet(rotated.toPublicJWK()));
            assertThat(factory.createDecoder(c).decode(assertion(rotated)).getSubject()).isEqualTo("c1");
            assertThat(target.requests()).hasSize(2); // refetched for the unknown kid
        }
    }

    private static String assertionWithTyp(final RSAKey signer, final String typ) throws Exception {
        final JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signer.getKeyID());
        if (typ != null) {
            header.type(new com.nimbusds.jose.JOSEObjectType(typ));
        }
        final SignedJWT jwt = new SignedJWT(header.build(), new JWTClaimsSet.Builder().issuer("c1").subject("c1")
                .audience(TOKEN_ENDPOINT).jwtID(UUID.randomUUID().toString()).issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60_000)).build());
        jwt.sign(new RSASSASigner(signer));
        return jwt.serialize();
    }

    @Test
    void theAssertionTypMayBeJwtAbsentOrClientAuthenticationJwt() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("jwks.client.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/json",
                    new JWKSet(key.toPublicJWK()).toString()));
            final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("jwks.client.test:" + target.port()),
                    host -> new java.net.InetAddress[] {java.net.InetAddress.getByAddress(host,
                            new byte[] {127, 0, 0, 1})});
            final var decoder = new GuardedClientAssertionDecoderFactory(guard).createDecoder(
                    client(target.url("http", "/jwks")));
            for (final String typ : new String[] {null, "JWT", "client-authentication+jwt"}) {
                assertThat(decoder.decode(assertionWithTyp(key, typ)).getSubject()).as(String.valueOf(typ))
                        .isEqualTo("c1");
            }
            assertThatThrownBy(() -> decoder.decode(assertionWithTyp(key, "at+jwt")))
                    .isInstanceOf(JwtException.class);
        }
    }
}
