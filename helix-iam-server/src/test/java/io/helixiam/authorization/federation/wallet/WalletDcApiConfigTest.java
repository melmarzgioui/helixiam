/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The W3C Digital Credentials API settings of a wallet connection ({@code dcApi.*}): stored form, defaults, the
 * effective expected origins, and the validator's rules. Only the {@code dcApi.*} field errors are looked at here (the
 * access-key rules have their own tests), so the validator gets a key store that knows no key.
 */
class WalletDcApiConfigTest {

    private static final RealmSigningKeys NO_KEYS = new RealmSigningKeys() {
        @Override
        public SigningKeyHandle resolve(final String realmId, final String keyRef) {
            throw new NoSuchElementException("Signing key not found in this realm");
        }

        @Override
        public String importKey(final String realmId, final String name, final String privateKeyPem,
                                final String certificateChainPem) {
            throw new UnsupportedOperationException();
        }
    };

    private static final Set<String> SERVED = Set.of("login.example.eu", "id.example.eu");
    private final WalletConfigValidator production =
            new WalletConfigValidator(NO_KEYS, DeploymentProfile.production(), SERVED);
    private final WalletConfigValidator dev =
            new WalletConfigValidator(NO_KEYS, DeploymentProfile.development(), SERVED);

    private static Map<String, String> stored(final String... pairs) {
        final Map<String, String> m = new LinkedHashMap<>();
        m.put("alias", "eudi-wallet");
        for (int i = 0; i < pairs.length; i += 2) {
            m.put(pairs[i], pairs[i + 1]);
        }
        return m;
    }

    private static Map<String, String> dcApiErrors(final WalletConfigValidator validator,
                                                   final Map<String, String> stored) {
        return validator.validateStored("acme", "eudi-wallet", "Wallet", stored).entrySet().stream()
                .filter(e -> e.getKey().startsWith("dcApi."))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    // ------------------------------------------------------------------ stored form

    @Test
    void defaults_dcApiIsOff_signed_noOrigins() {
        final WalletProviderConfig c = WalletProviderConfig.fromStored(stored());

        assertThat(c.dcApi().enabled()).isFalse();
        assertThat(c.dcApi().request()).isEqualTo(WalletProviderConfig.DcApi.RequestType.SIGNED);
        assertThat(c.dcApi().expectedOrigins()).isEmpty();
        assertThat(c.toStored()).doesNotContainKeys("dcApi.enabled", "dcApi.request", "dcApi.expectedOrigins");
    }

    @Test
    void storedSettings_roundTrip() {
        final WalletProviderConfig c = WalletProviderConfig.fromStored(stored("dcApi.enabled", "true",
                "dcApi.request", "unsigned", "dcApi.expectedOrigins", "[\"https://login.example.eu\"]"));

        assertThat(c.dcApi().enabled()).isTrue();
        assertThat(c.dcApi().request()).isEqualTo(WalletProviderConfig.DcApi.RequestType.UNSIGNED);
        assertThat(c.dcApi().expectedOrigins()).containsExactly("https://login.example.eu");
        assertThat(c.toStored()).containsEntry("dcApi.enabled", "true").containsEntry("dcApi.request", "unsigned")
                .containsEntry("dcApi.expectedOrigins", "[\"https://login.example.eu\"]");
        assertThat(WalletProviderConfig.fromStored(c.toStored())).isEqualTo(c);
    }

    @Test
    void malformedStoredValues_areFieldErrors() {
        assertThatThrownBy(() -> WalletProviderConfig.fromStored(stored("dcApi.enabled", "yes",
                "dcApi.request", "multisigned", "dcApi.expectedOrigins", "https://x")))
                .isInstanceOfSatisfying(WalletConfigFormatException.class, e -> assertThat(e.fieldErrors())
                        .containsKeys("dcApi.enabled", "dcApi.request", "dcApi.expectedOrigins"));
    }

    @Test
    void protocolIdentifiers_areTheOpenId4VpAppendixAOnes() {
        assertThat(WalletProviderConfig.DcApi.RequestType.SIGNED.protocol()).isEqualTo("openid4vp-v1-signed");
        assertThat(WalletProviderConfig.DcApi.RequestType.UNSIGNED.protocol()).isEqualTo("openid4vp-v1-unsigned");
    }

    // ------------------------------------------------------------------ effective origins

    @Test
    void effectiveOrigins_defaultToTheOriginOfTheIdpBaseUrl() {
        final WalletProviderConfig c = WalletProviderConfig.fromStored(stored("dcApi.enabled", "true"));

        assertThat(c.dcApi().effectiveOrigins("https://Login.Example.EU/")).containsExactly("https://login.example.eu");
        assertThat(c.dcApi().effectiveOrigins("https://login.example.eu:443/auth"))
                .containsExactly("https://login.example.eu");
        assertThat(c.dcApi().effectiveOrigins("http://localhost:9000")).containsExactly("http://localhost:9000");
    }

    @Test
    void effectiveOrigins_areTheConfiguredOnesWhenSet() {
        final WalletProviderConfig c = WalletProviderConfig.fromStored(stored("dcApi.enabled", "true",
                "dcApi.expectedOrigins", "[\"https://id.example.eu\",\"https://login.example.eu\"]"));

        assertThat(c.dcApi().effectiveOrigins("https://ignored.example.eu"))
                .containsExactly("https://id.example.eu", "https://login.example.eu");
    }

    // ------------------------------------------------------------------ validator

    @Test
    void validOrigins_onAServedHost_areAccepted() {
        assertThat(dcApiErrors(production, stored("dcApi.enabled", "true",
                "dcApi.expectedOrigins", "[\"https://login.example.eu\",\"https://id.example.eu:8443\"]"))).isEmpty();
        assertThat(dcApiErrors(production, stored("dcApi.enabled", "true"))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://login.example.eu/", "https://login.example.eu/path", "https://Login.example.eu",
            "HTTPS://login.example.eu", "https://login.example.eu:443", "https://u@login.example.eu",
            "https://login.example.eu?x=1", "https://login.example.eu#f", "login.example.eu", "origin:https://login.example.eu",
            "ftp://login.example.eu", "https://", " ", "http://login.example.eu"})
    void anOriginThatIsNotASerialisedHttpsOrigin_isRefused(final String origin) {
        assertThat(dcApiErrors(production, stored("dcApi.enabled", "true",
                "dcApi.expectedOrigins", "[\"" + origin + "\"]"))).containsKey("dcApi.expectedOrigins");
    }

    @Test
    void anOriginOnAHostThisServerDoesNotAnswerFor_isRefused() {
        assertThat(dcApiErrors(production, stored("dcApi.enabled", "true",
                "dcApi.expectedOrigins", "[\"https://evil.example.com\"]")))
                .containsEntry("dcApi.expectedOrigins", "https://evil.example.com is not a host this server answers "
                        + "for (the host of IDP_BASE_URL or one in HELIX_ALLOWED_HOSTS)");
    }

    @Test
    void duplicateOrTooManyOrigins_areRefused() {
        assertThat(dcApiErrors(production, stored("dcApi.enabled", "true", "dcApi.expectedOrigins",
                "[\"https://login.example.eu\",\"https://login.example.eu\"]"))).containsKey("dcApi.expectedOrigins");
        final String eleven = "[" + String.join(",", java.util.Collections.nCopies(11, "\"https://login.example.eu\""))
                + "]";
        assertThat(dcApiErrors(production, stored("dcApi.enabled", "true", "dcApi.expectedOrigins", eleven)))
                .containsKey("dcApi.expectedOrigins");
    }

    @Test
    void plainHttpLocalhost_isAcceptedInDevOnly() {
        final Map<String, String> local = stored("dcApi.enabled", "true", "dcApi.expectedOrigins",
                "[\"http://localhost:9000\"]");

        assertThat(dcApiErrors(production, local)).containsKey("dcApi.expectedOrigins");
        assertThat(dcApiErrors(new WalletConfigValidator(NO_KEYS, DeploymentProfile.development(),
                Set.of("localhost")), local)).isEmpty();
    }

    @Test
    void withoutAKnownServedHostSet_onlyTheOriginFormIsChecked() {
        final WalletConfigValidator unknownHosts = new WalletConfigValidator(NO_KEYS, DeploymentProfile.production());

        assertThat(dcApiErrors(unknownHosts, stored("dcApi.enabled", "true",
                "dcApi.expectedOrigins", "[\"https://anywhere.example.com\"]"))).isEmpty();
    }

    @Test
    void servedHosts_areTheIdpBaseUrlHostPlusTheAllowedHosts() {
        assertThat(WalletConfigValidator.servedHosts("https://Login.Example.EU:8443/x", "id.example.eu:9443, [::1] ,other"))
                .containsExactlyInAnyOrder("login.example.eu", "id.example.eu", "::1", "other");
        assertThat(WalletConfigValidator.servedHosts("https://login.example.eu", "")).containsExactly("login.example.eu");
        assertThat(List.of(dev)).isNotEmpty();
    }
}
