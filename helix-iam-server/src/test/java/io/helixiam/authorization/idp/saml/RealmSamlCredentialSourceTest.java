/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

import io.helixiam.authorization.amqp.ServiceProviderPublisher;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Per-realm SAML signing: the SAML IdP signing certificate must be derived from THIS realm's active
 * signing key (the same key the OIDC JWKS publishes), so every realm signs assertions as its own IdP
 * and a rotation of the realm key rotates the SAML cert too. Mirrors {@code RealmJwkSourceTest}.
 */
class RealmSamlCredentialSourceTest {

    private static KeyPair rsa() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate parseCert(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    private static PrivateKey parseKey(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    private static SamlIdpProperties props() {
        final SamlIdpProperties p = new SamlIdpProperties();
        p.setEnabled(true);
        p.setEntityId("https://idp.example/realms/master");
        return p;
    }

    @Test
    void certificateWrapsThisRealmsActiveKey() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final KeyPair kp = rsa();
        when(publisher.retrieveKeyPair("master")).thenReturn(kp);

        final RealmSamlCredentialSource source = new RealmSamlCredentialSource(publisher, props());
        final SamlIdpConfig cfg = source.forRealm("master");

        // The published cert carries exactly the realm's active public key, and the private key round-trips.
        assertArrayEquals(kp.getPublic().getEncoded(), parseCert(cfg.signingCertificate()).getPublicKey().getEncoded(),
                "SAML cert must wrap the realm's active signing public key");
        assertArrayEquals(kp.getPrivate().getEncoded(), parseKey(cfg.signingPrivateKey()).getEncoded(),
                "SAML private key must be the realm's active signing private key");
        assertEquals("https://idp.example/realms/master", cfg.idpEntityId());
    }

    @Test
    void selfSignedCertVerifiesUnderItsOwnKey() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final KeyPair kp = rsa();
        when(publisher.retrieveKeyPair("master")).thenReturn(kp);

        final SamlIdpConfig cfg = new RealmSamlCredentialSource(publisher, props()).forRealm("master");
        final X509Certificate cert = parseCert(cfg.signingCertificate());
        // A self-signed cert must validate under the public key it carries (proves it is a real signature).
        assertDoesNotThrow(() -> cert.verify(kp.getPublic()));
    }

    @Test
    void eachRealmSignsAsItsOwnIdp() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final KeyPair masterPair = rsa();
        final KeyPair govPair = rsa();
        when(publisher.retrieveKeyPair("master")).thenReturn(masterPair);
        when(publisher.retrieveKeyPair("gov")).thenReturn(govPair);

        final RealmSamlCredentialSource source = new RealmSamlCredentialSource(publisher, props());
        final byte[] masterKey = parseCert(source.forRealm("master").signingCertificate()).getPublicKey().getEncoded();
        final byte[] govKey = parseCert(source.forRealm("gov").signingCertificate()).getPublicKey().getEncoded();

        assertNotEquals(Base64.getEncoder().encodeToString(masterKey), Base64.getEncoder().encodeToString(govKey),
                "each realm must sign SAML as its own IdP, never sharing signing material");
    }

    @Test
    void certificateIsDeterministicForAStableKey() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final KeyPair kp = rsa();
        when(publisher.retrieveKeyPair("master")).thenReturn(kp);

        final RealmSamlCredentialSource source = new RealmSamlCredentialSource(publisher, props());
        // Byte-identical across calls (fixed serial + validity + deterministic RSA signature) → stable
        // metadata + stable SP-pinned fingerprints.
        assertEquals(source.forRealm("master").signingCertificate(), source.forRealm("master").signingCertificate());
    }

    @Test
    void rotationOfTheRealmKeyRotatesTheCertificate() throws Exception {
        final ServiceProviderPublisher publisher = mock(ServiceProviderPublisher.class);
        final KeyPair before = rsa();
        when(publisher.retrieveKeyPair("master")).thenReturn(before);

        // TTL 0 → every call refetches, simulating propagation after the 30s cache window elapses.
        final RealmSamlCredentialSource source = new RealmSamlCredentialSource(publisher, props(), 0L);
        final byte[] keyBefore = parseCert(source.forRealm("master").signingCertificate()).getPublicKey().getEncoded();

        final KeyPair after = rsa();
        when(publisher.retrieveKeyPair("master")).thenReturn(after);
        final byte[] keyAfter = parseCert(source.forRealm("master").signingCertificate()).getPublicKey().getEncoded();

        assertArrayEquals(after.getPublic().getEncoded(), keyAfter, "after rotation the SAML cert wraps the new key");
        assertNotEquals(Base64.getEncoder().encodeToString(keyBefore), Base64.getEncoder().encodeToString(keyAfter));
    }
}
