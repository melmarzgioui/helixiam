/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.testwallet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * A {@link RealmSigningKeys} holding one verifier access key (a {@link TestPki} leaf, EC P-256) under the reference
 * {@code software:<realm>/<name>} in each of the given realms; anything else is "not found", like the real store.
 */
public final class TestAccessKeys implements RealmSigningKeys {

    private final TestPki.Leaf leaf;
    private final String name;
    private final List<String> realms;

    public TestAccessKeys(final TestPki.Leaf leaf, final String name, final String... realms) {
        this.leaf = leaf;
        this.name = name;
        this.realms = List.of(realms);
    }

    /** The reference this store resolves in {@code realm}. */
    public String ref(final String realm) {
        return "software:" + realm + "/" + name;
    }

    @Override
    public SigningKeyHandle resolve(final String realmId, final String keyRef) {
        if (!realms.contains(realmId) || !ref(realmId).equals(keyRef)) {
            throw new NoSuchElementException("Signing key not found in this realm");
        }
        final JWSSigner signer;
        try {
            signer = new ECDSASigner((ECPrivateKey) leaf.privateKey());
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
        return new SigningKeyHandle() {
            @Override
            public String keyRef() {
                return keyRef;
            }

            @Override
            public JWSAlgorithm algorithm() {
                return JWSAlgorithm.ES256;
            }

            @Override
            public List<X509Certificate> certificateChain() {
                return leaf.chain();
            }

            @Override
            public JWSSigner signer() {
                return signer;
            }
        };
    }

    @Override
    public String importKey(final String realmId, final String keyName, final String privateKeyPem,
                            final String certificateChainPem) {
        throw new UnsupportedOperationException("test key store");
    }
}
