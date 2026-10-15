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
        assertThat(WalletVerifyLinkRules.anchorsWithin(verify(HIGH, ISSUERS.rootPem()),
                linkedConfig(ISSUERS.rootPem() + OTHER.rootPem(), null, null))).isTrue();
        assertThat(WalletVerifyLinkRules.anchorsWithin(verify(HIGH, OTHER.rootPem()),
                linkedConfig(ISSUERS.rootPem(), null, null))).isFalse();
        assertThat(WalletVerifyLinkRules.anchorsWithin(verifyAnchors("garbage"),
                linkedConfig(ISSUERS.rootPem(), null, null))).isFalse();
    }

    // pentest-b LOW: anchorsWithin compared only the PEM trustAnchors, so a connection relying on trusted lists
    // (no PEM anchors at all) always flagged a spurious warning, even against an identically-configured linked
    // connection. It must also compare trustedLists.sources and trustedLists.serviceTypes.

    @Test
    void sameTrustedListSources_noPemAnchorsEither_isWithin() {
        assertThat(WalletVerifyLinkRules.anchorsWithin(
                verifyTrustedLists("[\"eu-pid\"]", null),
                linkedConfig(null, "[\"eu-pid\"]", null))).isTrue();
    }

    @Test
    void aTrustedListSourceTheLinkedConnectionDoesNotName_isNotWithin() {
        assertThat(WalletVerifyLinkRules.anchorsWithin(
                verifyTrustedLists("[\"eu-pid\",\"extra\"]", null),
                linkedConfig(null, "[\"eu-pid\"]", null))).isFalse();
    }

    @Test
    void aServiceTypeNarrowerThanTheLinkedConnections_isWithin_aWiderOneIsNot() {
        assertThat(WalletVerifyLinkRules.anchorsWithin(
                verifyTrustedLists("[\"eu-pid\"]", "[\"PID\"]"),
                linkedConfig(null, "[\"eu-pid\"]", "[\"PID\",\"MDL\"]"))).isTrue();
        assertThat(WalletVerifyLinkRules.anchorsWithin(
                verifyTrustedLists("[\"eu-pid\"]", "[\"PID\",\"MDL\"]"),
                linkedConfig(null, "[\"eu-pid\"]", "[\"PID\"]"))).isFalse();
    }

    @Test
    void emptyServiceTypesOnTheLinkedConnection_meansEveryType_soAnyVerifyServiceTypeIsWithin() {
        assertThat(WalletVerifyLinkRules.anchorsWithin(
                verifyTrustedLists("[\"eu-pid\"]", "[\"PID\"]"),
                linkedConfig(null, "[\"eu-pid\"]", null))).isTrue();
    }

    private static WalletProviderConfig verifyAnchors(final String anchors) {
        return verify(HIGH, anchors);
    }

    private static WalletProviderConfig verifyTrustedLists(final String sources, final String serviceTypes) {
        final Map<String, String> m = new HashMap<>();
        m.put("subject.strategy", "NONE");
        m.put("verify.linkedProvider", "eudi-wallet");
        m.put("minimumLoa", HIGH);
        if (sources != null) {
            m.put("trustedLists.sources", sources);
        }
        if (serviceTypes != null) {
            m.put("trustedLists.serviceTypes", serviceTypes);
        }
        return WalletProviderConfig.fromStored("eudi-verify", "Verify", m);
    }

    private static WalletProviderConfig linkedConfig(final String anchors, final String sources,
            final String serviceTypes) {
        final Map<String, String> m = new HashMap<>();
        m.put("subject.strategy", "ADMINISTRATIVE_NUMBER");
        m.put("minimumLoa", HIGH);
        if (anchors != null) {
            m.put("trustAnchors", anchors);
        }
        if (sources != null) {
            m.put("trustedLists.sources", sources);
        }
        if (serviceTypes != null) {
            m.put("trustedLists.serviceTypes", serviceTypes);
        }
        return WalletProviderConfig.fromStored("eudi-wallet", "Wallet", m);
    }
}
