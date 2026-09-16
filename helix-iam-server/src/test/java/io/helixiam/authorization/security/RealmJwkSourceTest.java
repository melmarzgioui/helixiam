/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import io.helixiam.authorization.amqp.ServiceProviderPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM multi-tenant (MT-3): the JWK source serves the CURRENT realm's key and caches per realm,
 * so two realms never share signing material (a leak would let one realm's tokens verify under another).
 */
class RealmJwkSourceTest {

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
    }

    private static KeyPair rsa() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static List<JWK> publish(final RealmJwkSource source) {
        return source.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
    }

    @Test
    void servesEachRealmsOwnKey_withoutLeakingAcrossRealms() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final KeyPair masterPair = rsa();
        final KeyPair govPair = rsa();
        when(publisher.retrieveKeyPair("master")).thenReturn(masterPair);
        when(publisher.retrieveKeyPair("gov")).thenReturn(govPair);
        when(publisher.retrieveVerificationKeys("master")).thenReturn(new ArrayList<>());
        when(publisher.retrieveVerificationKeys("gov")).thenReturn(new ArrayList<>());

        final RealmJwkSource source = new RealmJwkSource(publisher);

        RealmContextHolder.set("master");
        final String masterKid = publish(source).get(0).getKeyID();

        RealmContextHolder.set("gov");
        final String govKid = publish(source).get(0).getKeyID();

        assertNotEquals(masterKid, govKid, "each realm must publish its own distinct key");

        // Back to master: the cached master key is still served (not gov's).
        RealmContextHolder.set("master");
        assertEquals(masterKid, publish(source).get(0).getKeyID());
    }

    /**
     * A2 (FAPI2): the realm's active RSA key must be usable for PS256 signing (RSASSA-PSS), not only
     * RS256 — FAPI2 forbids RS256 for signatures. PS256 reuses the same RSA key material, so a PS256
     * signing selection must resolve to exactly the active (private) key.
     */
    @Test
    void ps256SigningSelection_resolvesTheActivePrivateKey() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        when(publisher.retrieveKeyPair("master")).thenReturn(rsa());
        when(publisher.retrieveVerificationKeys("master")).thenReturn(new ArrayList<>());
        final RealmJwkSource source = new RealmJwkSource(publisher);
        RealmContextHolder.set("master");

        final List<JWK> ps256 = source.get(
                new JWKSelector(new JWKMatcher.Builder().algorithm(JWSAlgorithm.PS256).build()), null);

        assertFalse(ps256.isEmpty(), "PS256 signing selection must match the active RSA key (FAPI2)");
        assertTrue(ps256.get(0).isPrivate(), "the PS256 signing key must carry the private key");
        assertEquals(JWSAlgorithm.PS256, ps256.get(0).getAlgorithm());
    }

    /** RS256 must keep working after A2 (backward compatibility for existing clients). */
    @Test
    void rs256SigningSelection_stillResolvesTheActivePrivateKey() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        when(publisher.retrieveKeyPair("master")).thenReturn(rsa());
        when(publisher.retrieveVerificationKeys("master")).thenReturn(new ArrayList<>());
        final RealmJwkSource source = new RealmJwkSource(publisher);
        RealmContextHolder.set("master");

        final List<JWK> rs256 = source.get(
                new JWKSelector(new JWKMatcher.Builder().algorithm(JWSAlgorithm.RS256).build()), null);

        assertFalse(rs256.isEmpty(), "RS256 signing selection must still match the active key");
        assertTrue(rs256.get(0).isPrivate());
        assertEquals(JWSAlgorithm.RS256, rs256.get(0).getAlgorithm());
    }
}
