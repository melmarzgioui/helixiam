/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Security review item 8: a verify-only connection links to a real, sign-in capable, not weaker wallet connection. */
class WalletVerifyLinkRulesTest {

    private static final TestPki ISSUERS = TestPki.create("Link PID Provider");
    private static final TestPki OTHER = TestPki.create("Other PID Provider");

    private static WalletProviderConfig verify(final String minimumLoa, final String anchors) {
        final Map<String, String> m = new HashMap<>();
        m.put("subject.strategy", "NONE");
        m.put("verify.linkedProvider", "eudi-wallet");
        m.put("minimumLoa", minimumLoa);
        m.put("trustAnchors", anchors);
        return WalletProviderConfig.fromStored("eudi-verify", "Verify", m);
    }

    private static Map<String, String> linked(final String strategy, final String minimumLoa, final String anchors) {
        final Map<String, String> m = new HashMap<>();
        m.put("subject.strategy", strategy);
        m.put("minimumLoa", minimumLoa);
        m.put("trustAnchors", anchors);
        return m;
    }

    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";

    @Test
    void theLinkedConnection_mustExist_beAWallet_andSignIn() {
        assertThat(WalletVerifyLinkRules.problems(verify(HIGH, ISSUERS.rootPem()), null, null))
                .containsKey("verify.linkedProvider");
        assertThat(WalletVerifyLinkRules.problems(verify(HIGH, ISSUERS.rootPem()), "oidc",
                linked("ADMINISTRATIVE_NUMBER", HIGH, ISSUERS.rootPem()))).containsKey("verify.linkedProvider");
        assertThat(WalletVerifyLinkRules.problems(verify(HIGH, ISSUERS.rootPem()), "eudi-wallet",
                linked("NONE", HIGH, ISSUERS.rootPem()))).containsKey("verify.linkedProvider");
        assertThat(WalletVerifyLinkRules.problems(verify(HIGH, ISSUERS.rootPem()), "eudi-wallet",
                linked("ADMINISTRATIVE_NUMBER", HIGH, ISSUERS.rootPem()))).isEmpty();
    }

    @Test
    void theMinimumLoa_isAtLeastTheLinkedConnections() {
        assertThat(WalletVerifyLinkRules.problems(verify(SUBSTANTIAL, ISSUERS.rootPem()), "eudi-wallet",
                linked("ADMINISTRATIVE_NUMBER", HIGH, ISSUERS.rootPem()))).containsKey("minimumLoa");
        assertThat(WalletVerifyLinkRules.problems(verify(HIGH, ISSUERS.rootPem()), "eudi-wallet",
                linked("ADMINISTRATIVE_NUMBER", SUBSTANTIAL, ISSUERS.rootPem()))).isEmpty();
    }

    @Test
    void trustAnchorsTheLinkedConnectionDoesNotTrust_areOnlyFlagged() {
        assertThat(WalletVerifyLinkRules.anchorsWithin(verify(HIGH, ISSUERS.rootPem()).trustAnchors(),
                ISSUERS.rootPem() + OTHER.rootPem())).isTrue();
        assertThat(WalletVerifyLinkRules.anchorsWithin(verify(HIGH, OTHER.rootPem()).trustAnchors(),
                ISSUERS.rootPem())).isFalse();
        assertThat(WalletVerifyLinkRules.anchorsWithin("garbage", ISSUERS.rootPem())).isFalse();
    }
}
