/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.startup;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.helixiam.authorization.federation.FederationProviderProperties;
import io.helixiam.authorization.federation.wallet.WalletProviderConfig;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;

import java.util.Map;

class ProductionReadinessCheckTest {

    private static Environment env(final boolean dev) {
        final MockEnvironment e = new MockEnvironment();
        if (dev) {
            e.setActiveProfiles("dev");
        }
        return e;
    }

    private static FederationProviderProperties noWallets() {
        return new FederationProviderProperties();
    }

    private static FederationProviderProperties withWallet(final WalletProviderConfig wallet) {
        final FederationProviderProperties federation = new FederationProviderProperties();
        federation.setWallet(java.util.List.of(wallet));
        return federation;
    }

    /** A fully-configured, secure production posture, no wallet providers. */
    private static ProductionReadinessCheck secureProd(final String encKey, final boolean allowPlaintext,
                                                       final String idp, final String sp) {
        return new ProductionReadinessCheck(env(false), encKey, allowPlaintext, idp, sp,
                false, false, true, false, false, noWallets());
    }

    @Test
    void failsFast_whenEncryptionUnset_outsideDev_withoutOptIn() {
        final ProductionReadinessCheck c = secureProd("", false, "https://idp", "https://sp");
        assertThatThrownBy(c::check)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("DB_ENCRYPTION");
    }

    @Test
    void allowsPlaintext_whenExplicitlyOptedIn() {
        final ProductionReadinessCheck c = secureProd("", true, "https://idp", "https://sp");
        assertThatCode(c::check).doesNotThrowAnyException();
    }

    @Test
    void failsFast_whenBaseUrlsUnset_outsideDev() {
        assertThatThrownBy(() -> secureProd("deadbeef", false, "", "https://sp").check())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("IDP_BASE_URL");
        assertThatThrownBy(() -> secureProd("deadbeef", false, "https://idp", "").check())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SP_BASE_URL");
    }

    @Test
    void devProfile_downgradesEveryFatalCheck() {
        final ProductionReadinessCheck c = new ProductionReadinessCheck(env(true),
                "", false, "", "", true, true, false, true, true,
                withWallet(directPostWallet()));
        assertThatCode(c::check).doesNotThrowAnyException();
    }

    @Test
    void secureProdPosture_startsCleanly() {
        final ProductionReadinessCheck c = secureProd("deadbeefdeadbeef", false, "https://idp", "https://sp");
        assertThatCode(c::check).doesNotThrowAnyException();
    }

    // ------------------------------------------------------------------------------------------- Task 22: wallet

    private static WalletProviderConfig directPostWallet() {
        return WalletProviderConfig.fromStored("eudi-wallet", "EU Digital Identity Wallet",
                Map.of("accessKeyRef", "software:acme/eudi-access", "responseMode", "direct_post"));
    }

    private static WalletProviderConfig encryptedWallet() {
        return WalletProviderConfig.fromStored("eudi-wallet", "EU Digital Identity Wallet",
                Map.of("accessKeyRef", "software:acme/eudi-access"));
    }

    @Test
    void failsFast_whenAWalletProviderUsesDirectPost_outsideDev() {
        final ProductionReadinessCheck c = new ProductionReadinessCheck(env(false), "deadbeefdeadbeef", false,
                "https://idp", "https://sp", false, false, true, false, false, withWallet(directPostWallet()));

        assertThatThrownBy(c::check).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("direct_post").hasMessageContaining("eudi-wallet");
    }

    @Test
    void devProfile_allowsADirectPostWalletProvider() {
        final ProductionReadinessCheck c = new ProductionReadinessCheck(env(true), "deadbeefdeadbeef", false,
                "https://idp", "https://sp", false, false, true, false, false, withWallet(directPostWallet()));

        assertThatCode(c::check).doesNotThrowAnyException();
    }

    @Test
    void failsFast_whenAWalletProviderIsConfigured_withoutEncryption_evenIfPlaintextIsOtherwiseAllowed() {
        final ProductionReadinessCheck c = new ProductionReadinessCheck(env(false), "", true, "https://idp",
                "https://sp", false, false, true, false, false, withWallet(encryptedWallet()));

        assertThatThrownBy(c::check).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("wallet").hasMessageContaining("DB_ENCRYPTION");
    }

    @Test
    void encryptedWalletProvider_outsideDev_startsCleanly() {
        final ProductionReadinessCheck c = new ProductionReadinessCheck(env(false), "deadbeefdeadbeef", false,
                "https://idp", "https://sp", false, false, true, false, false, withWallet(encryptedWallet()));

        assertThatCode(c::check).doesNotThrowAnyException();
    }

    @Test
    void noWalletProviders_neverFailOnWalletChecks() {
        final ProductionReadinessCheck c = new ProductionReadinessCheck(env(false), "", true, "https://idp",
                "https://sp", false, false, true, false, false, noWallets());

        assertThatCode(c::check).doesNotThrowAnyException();
    }
}
