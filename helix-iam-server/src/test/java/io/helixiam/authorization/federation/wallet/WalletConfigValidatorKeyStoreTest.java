/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link WalletConfigValidator} against the real {@link RealmSigningKeys} store (the e2e context): a key reference is
 * honoured only in its own realm, and a stored key that cannot be used is a field error, never an exception.
 */
class WalletConfigValidatorKeyStoreTest extends AbstractE2eTest {

    private static final TestPki PKI = TestPki.create("KeyStore Access");
    private static final TestPki.Leaf ACCESS = PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestPki ISSUERS = TestPki.create("KeyStore PID");

    private WalletConfigValidator validator;
    private String realm;
    private String keyRef;

    @BeforeEach
    void setUp() {
        validator = context.getBean(WalletConfigValidator.class);
        realm = E2eSeed.unique("wcfg");
        keyRef = context.getBean(RealmSigningKeys.class).importKey(realm, "eudi-access",
                WalletConfigValidatorTest.pkcs8Pem(ACCESS.privateKey()),
                TestPki.pem(ACCESS.certificate()) + PKI.intermediatePem());
    }

    private Map<String, String> config() {
        final Map<String, String> m = new HashMap<>();
        m.put("alias", "eudi-wallet");
        m.put("accessKeyRef", keyRef);
        m.put("trustAnchors", ISSUERS.rootPem());
        return m;
    }

    @Test
    void keyRefInItsOwnRealm_isAccepted() {
        assertThat(validator.validate(realm, WalletProviderConfig.fromStored(config()))).isEmpty();
    }

    @Test
    void keyRefOfAnotherRealm_isNotFound() {
        final String other = E2eSeed.unique("wcfg-other");
        assertThat(validator.validate(other, WalletProviderConfig.fromStored(config())))
                .containsEntry("accessKeyRef", "Signing key not found in this realm");
    }

    @Test
    void corruptStoredKey_isAFieldError() {
        final JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(s ->
                jdbc.update("UPDATE verifier_signing_key SET alg = 'ES384' WHERE realm_id = ?", realm));
        assertThat(validator.validate(realm, WalletProviderConfig.fromStored(config())))
                .containsEntry("accessKeyRef", "The key behind accessKeyRef cannot be used");
    }
}
