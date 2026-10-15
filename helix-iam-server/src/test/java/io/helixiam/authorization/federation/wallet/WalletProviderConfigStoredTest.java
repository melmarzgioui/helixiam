/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.ProviderSecretKeys;
import io.helixiam.authorization.federation.wallet.dcql.PidQuerySpec;
import io.helixiam.authorization.federation.wallet.mdoc.CborLimits;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link WalletProviderConfig}: defaults, the flat stored map ({@code fromStored} / {@code toStored}), derived views. */
class WalletProviderConfigStoredTest {

    private static final TestPki.Leaf ACCESS = TestPki.create("Stored").issueLeaf(TestPki.LeafSpec.defaults());
    private static final String PRIVATE_PEM = WalletConfigValidatorTest.pkcs8Pem(ACCESS.privateKey());

    @Test
    void emptyStoredMap_givesTheDefaults() {
        final WalletProviderConfig c = WalletProviderConfig.fromStored(Map.of("alias", "eudi-wallet"));
        assertThat(c.alias()).isEqualTo("eudi-wallet");
        assertThat(c.clientIdScheme()).isEqualTo(WalletProviderConfig.ClientIdScheme.X509_HASH);
        assertThat(c.invocationScheme()).isEqualTo("haip-vp");
        assertThat(c.responseMode()).isEqualTo(WalletProviderConfig.ResponseMode.DIRECT_POST_JWT);
        assertThat(c.requestUriMethod()).isEqualTo(WalletProviderConfig.RequestUriMethod.GET);
        assertThat(c.transactionTtlSeconds()).isEqualTo(300);
        assertThat(c.credentialFormats()).containsExactly("dc+sd-jwt", "mso_mdoc");
        assertThat(c.pid().sdJwtVcts()).containsExactly("urn:eudi:pid:1", "urn:eudi:pid:de:1");
        assertThat(c.pid().mdocDoctype()).isEqualTo("eu.europa.ec.eudi.pid.1");
        assertThat(c.pid().requestedClaims()).containsExactly("given_name", "family_name", "birthdate")
                .doesNotContain("age_over_18");
        assertThat(c.customCredentialQueries()).isEmpty();
        assertThat(c.revocationChecking()).isEqualTo(TrustAnchors.RevocationMode.HARD_FAIL);
        assertThat(c.statusList().required()).isFalse();
        assertThat(c.statusList().onUnavailable()).isEqualTo(StatusPolicy.OnUnavailable.FAIL_CLOSED);
        assertThat(c.statusList().maxCacheSeconds()).isEqualTo(900);
        assertThat(c.statusList().allowedHosts()).isEmpty();
        assertThat(c.subject().strategy()).isEqualTo(WalletProviderConfig.Subject.Strategy.ADMINISTRATIVE_NUMBER);
        assertThat(c.subject().acknowledgeWeakSubject()).isFalse();
        assertThat(c.minimumLoa()).isEqualTo("http://eidas.europa.eu/LoA/high");
        assertThat(c.clockSkewSeconds()).isEqualTo(60);
        assertThat(c.allowLegacyVcSdJwtTyp()).isFalse();
        assertThat(c.limits().maxJwtBytes()).isEqualTo(64 * 1024);
        assertThat(c.limits().cborLimits()).isEqualTo(CborLimits.DEFAULTS);
    }

    @Test
    void fromStored_parsesJsonListsAndCaseInsensitiveEnums() {
        final Map<String, String> m = new HashMap<>();
        m.put("alias", "w");
        m.put("clientIdScheme", "X509_San_Dns");
        m.put("clientIdHost", "verifier.example.eu");
        m.put("responseMode", "DIRECT_POST");
        m.put("requestUriMethod", "Post");
        m.put("invocationScheme", "eudi-openid4vp");
        m.put("transactionTtlSeconds", "120");
        m.put("credentialFormats", "[\"mso_mdoc\"]");
        m.put("pid.sdJwtVcts", "[\"urn:eudi:pid:1\",\"urn:eudi:pid:nl:1\"]");
        m.put("pid.mdocDoctype", "eu.europa.ec.eudi.pid.nl.1");
        m.put("pid.requestedClaims", "[\"birthdate\",\"address.locality\"]");
        m.put("revocationChecking", "hard_fail");
        m.put("statusList.required", "TRUE");
        m.put("statusList.onUnavailable", "fail_open_with_audit");
        m.put("statusList.maxCacheSeconds", "60");
        m.put("statusList.allowedHosts", "[\"status.example.eu\"]");
        m.put("subject.strategy", "attribute_tuple");
        m.put("subject.acknowledgeWeakSubject", "true");
        m.put("minimumLoa", "http://eidas.europa.eu/LoA/substantial");
        m.put("clockSkewSeconds", "30");
        m.put("allowLegacyVcSdJwtTyp", "true");
        m.put("limits.maxJwtBytes", "1000");
        m.put("limits.cborMaxDepth", "8");
        m.put("limits.cborMaxItems", "500");
        m.put("limits.cborMaxBytes", "2048");
        final WalletProviderConfig c = WalletProviderConfig.fromStored(m);

        assertThat(c.clientIdScheme()).isEqualTo(WalletProviderConfig.ClientIdScheme.X509_SAN_DNS);
        assertThat(c.responseMode()).isEqualTo(WalletProviderConfig.ResponseMode.DIRECT_POST);
        assertThat(c.requestUriMethod()).isEqualTo(WalletProviderConfig.RequestUriMethod.POST);
        assertThat(c.invocationScheme()).isEqualTo("eudi-openid4vp");
        assertThat(c.transactionTtlSeconds()).isEqualTo(120);
        assertThat(c.credentialFormats()).containsExactly("mso_mdoc");
        assertThat(c.pid().sdJwtVcts()).containsExactly("urn:eudi:pid:1", "urn:eudi:pid:nl:1");
        assertThat(c.pid().mdocDoctype()).isEqualTo("eu.europa.ec.eudi.pid.nl.1");
        assertThat(c.pid().requestedClaims()).containsExactly("birthdate", "address.locality");
        assertThat(c.revocationChecking()).isEqualTo(TrustAnchors.RevocationMode.HARD_FAIL);
        assertThat(c.statusList().toStatusPolicy()).isEqualTo(new StatusPolicy(true,
                StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT, Duration.ofSeconds(60), List.of("status.example.eu")));
        assertThat(c.subject().strategy()).isEqualTo(WalletProviderConfig.Subject.Strategy.ATTRIBUTE_TUPLE);
        assertThat(c.subject().acknowledgeWeakSubject()).isTrue();
        assertThat(c.minimumLoa()).isEqualTo("http://eidas.europa.eu/LoA/substantial");
        assertThat(c.clockSkewSeconds()).isEqualTo(30);
        assertThat(c.allowLegacyVcSdJwtTyp()).isTrue();
        assertThat(c.limits().maxJwtBytes()).isEqualTo(1000);
        assertThat(c.limits().cborLimits()).isEqualTo(new CborLimits(8, 500, 2048));
    }

    @Test
    void wireValuesOfEnums_areAccepted() {
        final WalletProviderConfig c = WalletProviderConfig.fromStored(Map.of("clientIdScheme", "x509_hash",
                "responseMode", "direct_post.jwt"));
        assertThat(c.clientIdScheme().value()).isEqualTo("x509_hash");
        assertThat(c.responseMode().value()).isEqualTo("direct_post.jwt");
    }

    @Test
    void storedStatusPolicy_defaults() {
        assertThat(WalletProviderConfig.fromStored(Map.of()).statusList().toStatusPolicy()).isEqualTo(
                new StatusPolicy(false, StatusPolicy.OnUnavailable.FAIL_CLOSED, Duration.ofSeconds(900), List.of()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"credentialFormats", "pid.sdJwtVcts", "pid.requestedClaims", "statusList.allowedHosts",
            "customCredentialQueries"})
    void listThatIsNoJsonArrayOfStrings_isRefused_namingTheField(final String key) {
        for (final String bad : List.of("dc+sd-jwt", "{\"a\":1}", "[1]", "[null]")) {
            assertThatThrownBy(() -> WalletProviderConfig.fromStored(Map.of(key, bad)))
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(key);
        }
    }

    @Test
    void unknownEnumOrNumber_isRefused_namingTheField() {
        assertThatThrownBy(() -> WalletProviderConfig.fromStored(Map.of("responseMode", "fragment")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("responseMode");
        assertThatThrownBy(() -> WalletProviderConfig.fromStored(Map.of("transactionTtlSeconds", "abc")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("transactionTtlSeconds");
        assertThatThrownBy(() -> WalletProviderConfig.fromStored(Map.of("statusList.required", "yes")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("statusList.required");
    }

    /** HAIP §5: the aki Trusted Authorities Query is sent by default under the HAIP profile, settable per provider. */
    @Test
    void trustedAuthorities_defaultOnUnderHaip_offOtherwise_andAnExplicitValueWins() {
        final WalletProviderConfig haip = WalletProviderConfig.fromStored(Map.of("alias", "w"));
        assertThat(haip.trustedAuthorities()).isNull();
        assertThat(haip.sendsTrustedAuthorities()).as("x509_hash + direct_post.jwt is the HAIP profile").isTrue();

        assertThat(WalletProviderConfig.fromStored(Map.of("alias", "w", "clientIdScheme", "x509_san_dns"))
                .sendsTrustedAuthorities()).isFalse();
        assertThat(WalletProviderConfig.fromStored(Map.of("alias", "w", "responseMode", "direct_post"))
                .sendsTrustedAuthorities()).isFalse();
        assertThat(WalletProviderConfig.fromStored(Map.of("alias", "w", "dcql.trustedAuthorities", "false"))
                .sendsTrustedAuthorities()).isFalse();
        assertThat(WalletProviderConfig.fromStored(Map.of("alias", "w", "clientIdScheme", "x509_san_dns",
                "dcql.trustedAuthorities", "TRUE")).sendsTrustedAuthorities()).isTrue();
        assertThat(WalletProviderConfig.fromStored(Map.of("alias", "w")).toStored())
                .doesNotContainKey("dcql.trustedAuthorities");
    }

    @Test
    void trustedAuthorities_thatIsNoBoolean_isRefused_namingTheField() {
        assertThatThrownBy(() -> WalletProviderConfig.fromStored(Map.of("alias", "w", "dcql.trustedAuthorities",
                "sometimes"))).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("dcql.trustedAuthorities");
    }

    @Test
    void storedRoundTrip_isLossless() {
        final WalletProviderConfig original = full();
        final Map<String, String> merged = new LinkedHashMap<>(original.toStored());
        merged.putAll(original.storedSecrets());
        assertThat(WalletProviderConfig.fromStored(merged)).isEqualTo(original);
    }

    @Test
    void toStored_neverEmitsThePrivateKey() {
        final WalletProviderConfig original = full();
        final Map<String, String> plain = original.toStored();

        assertThat(plain).doesNotContainKey("accessCertificatePrivateKey");
        assertThat(plain.values()).noneMatch(v -> v.contains("PRIVATE KEY"));
        assertThat(plain.toString()).doesNotContain("PRIVATE KEY").doesNotContain(PRIVATE_PEM.substring(40, 80));
        // Every key toStored emits is a plain (non-secret) key for every wallet protocol alias.
        for (final String protocol : List.of("eudi-wallet", "openid4vp", "wallet")) {
            assertThat(plain.keySet()).noneMatch(k -> ProviderSecretKeys.isSecret(protocol, k));
            assertThat(ProviderSecretKeys.split(protocol, plain).secrets()).isEmpty();
        }
        // The secret is only available from the explicitly named accessor, and it is a declared provider secret.
        assertThat(original.storedSecrets()).containsOnlyKeys("accessCertificatePrivateKey");
        for (final String protocol : List.of("eudi-wallet", "openid4vp", "wallet", "EUDI-WALLET")) {
            assertThat(ProviderSecretKeys.isSecret(protocol, "accessCertificatePrivateKey")).isTrue();
        }
        assertThat(WalletProviderConfig.fromStored(Map.of()).storedSecrets()).isEmpty();
    }

    @Test
    void toString_redactsThePrivateKey() {
        final String s = full().toString();
        assertThat(s).doesNotContain("PRIVATE KEY").doesNotContain(PRIVATE_PEM.substring(40, 80));
        assertThat(s).contains("eudi-wallet");
        assertThat(full().pid().toString() + full().statusList() + full().subject() + full().limits())
                .doesNotContain("PRIVATE KEY");
    }

    @Test
    void pidQuerySpec_andAcceptedVcts_comeFromTheSameSource() {
        final WalletProviderConfig c = full();
        final PidQuerySpec spec = c.pid().toQuerySpec();
        assertThat(spec).isEqualTo(new PidQuerySpec(List.of("urn:eudi:pid:1", "urn:eudi:pid:de:1", "urn:eudi:pid:nl:1"),
                "eu.europa.ec.eudi.pid.1", List.of("given_name", "birthdate")));
        assertThat(c.pid().acceptedVcts()).isEqualTo(Set.copyOf(spec.sdJwtVcts()));
        assertThat(c.pid().acceptedDoctype()).isEqualTo(spec.mdocDoctype());

        final WalletProviderConfig defaults = WalletProviderConfig.fromStored(Map.of());
        assertThat(defaults.pid().acceptedVcts()).isEqualTo(Set.copyOf(defaults.pid().toQuerySpec().sdJwtVcts()));
    }

    @Test
    void acceptedVcts_isUnmodifiable() {
        assertThatThrownBy(() -> full().pid().acceptedVcts().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    /** Every field away from its default, including the dev-only raw key. */
    private static WalletProviderConfig full() {
        final Map<String, String> m = new HashMap<>();
        m.put("alias", "eudi-wallet");
        m.put("displayName", "EU Digital Identity Wallet");
        m.put("clientIdScheme", "x509_san_dns");
        m.put("clientIdHost", "verifier.example.eu");
        m.put("accessCertificateChain", TestPki.pem(ACCESS.certificate()));
        m.put("accessCertificatePrivateKey", PRIVATE_PEM);
        m.put("registrationCertificate", TestPki.pem(ACCESS.certificate()));
        m.put("invocationScheme", "openid4vp");
        m.put("responseMode", "direct_post");
        m.put("requestUriMethod", "post");
        m.put("transactionTtlSeconds", "600");
        m.put("credentialFormats", "[\"dc+sd-jwt\"]");
        m.put("pid.sdJwtVcts", "[\"urn:eudi:pid:1\",\"urn:eudi:pid:de:1\",\"urn:eudi:pid:nl:1\"]");
        m.put("pid.requestedClaims", "[\"given_name\",\"birthdate\"]");
        m.put("customCredentialQueries", "[\"{\\\"id\\\":\\\"x\\\"}\"]");
        m.put("trustAnchors", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
        m.put("revocationChecking", "OFF");
        m.put("statusList.required", "true");
        m.put("statusList.onUnavailable", "FAIL_OPEN_WITH_AUDIT");
        m.put("statusList.maxCacheSeconds", "120");
        m.put("statusList.allowedHosts", "[\"status.example.eu\",\"status2.example.eu\"]");
        m.put("subject.strategy", "ATTRIBUTE_TUPLE");
        m.put("subject.acknowledgeWeakSubject", "true");
        m.put("minimumLoa", "http://eidas.europa.eu/LoA/substantial");
        m.put("clockSkewSeconds", "10");
        m.put("allowLegacyVcSdJwtTyp", "true");
        m.put("limits.maxJwtBytes", "32768");
        m.put("limits.cborMaxDepth", "12");
        m.put("limits.cborMaxItems", "5000");
        m.put("limits.cborMaxBytes", "131072");
        m.put("dcql.trustedAuthorities", "true");
        return WalletProviderConfig.fromStored(m);
    }
}
