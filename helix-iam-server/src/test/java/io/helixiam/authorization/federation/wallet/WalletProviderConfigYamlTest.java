/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.FederationProviderProperties;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code helix.federation.wallet[*]} binds from YAML the way the server binds {@link FederationProviderProperties}. */
class WalletProviderConfigYamlTest {

    private static FederationProviderProperties bind(final String yaml) throws Exception {
        final List<PropertySource<?>> sources = new YamlPropertySourceLoader().load("test",
                new ByteArrayResource(yaml.getBytes(StandardCharsets.UTF_8)));
        final StandardEnvironment env = new StandardEnvironment();
        sources.forEach(env.getPropertySources()::addFirst);
        return new Binder(ConfigurationPropertySources.get(env))
                .bind("helix.federation", Bindable.of(FederationProviderProperties.class))
                .orElseGet(FederationProviderProperties::new);
    }

    @Test
    void specSection9Yaml_bindsEveryField() throws Exception {
        final FederationProviderProperties p = bind("""
                helix:
                  federation:
                    wallet:
                      - alias: eudi-wallet
                        displayName: "EU Digital Identity Wallet"
                        clientIdScheme: x509_san_dns
                        clientIdHost: id.example.eu
                        accessCertificateChain: |
                          -----BEGIN CERTIFICATE-----
                          MIIB
                          -----END CERTIFICATE-----
                        accessKeyRef: software:acme/eudi-access
                        invocationScheme: eudi-openid4vp
                        responseMode: direct_post.jwt
                        requestUriMethod: post
                        transactionTtlSeconds: 240
                        credentialFormats: [dc+sd-jwt, mso_mdoc]
                        pid:
                          sdJwtVcts: ["urn:eudi:pid:1", "urn:eudi:pid:de:1"]
                          mdocDoctype: "eu.europa.ec.eudi.pid.1"
                          requestedClaims: [given_name, family_name, birthdate, address.locality]
                        customCredentialQueries: []
                        trustAnchors: |
                          -----BEGIN CERTIFICATE-----
                          MIIC
                          -----END CERTIFICATE-----
                        revocationChecking: HARD_FAIL
                        statusList:
                          required: true
                          onUnavailable: FAIL_OPEN_WITH_AUDIT
                          maxCacheSeconds: 600
                          allowedHosts: [status.example.eu]
                        subject:
                          strategy: ATTRIBUTE_TUPLE
                          acknowledgeWeakSubject: true
                        minimumLoa: http://eidas.europa.eu/LoA/substantial
                        clockSkewSeconds: 30
                        allowLegacyVcSdJwtTyp: true
                        limits:
                          maxJwtBytes: 32768
                          cborMaxDepth: 8
                """);
        assertThat(p.getWallet()).hasSize(1);
        final WalletProviderConfig c = p.getWallet().get(0);
        assertThat(c.alias()).isEqualTo("eudi-wallet");
        assertThat(c.displayName()).isEqualTo("EU Digital Identity Wallet");
        assertThat(c.clientIdScheme()).isEqualTo(WalletProviderConfig.ClientIdScheme.X509_SAN_DNS);
        assertThat(c.clientIdHost()).isEqualTo("id.example.eu");
        assertThat(c.accessCertificateChain()).startsWith("-----BEGIN CERTIFICATE-----\nMIIB");
        assertThat(c.accessKeyRef()).isEqualTo("software:acme/eudi-access");
        assertThat(c.accessCertificatePrivateKey()).isNull();
        assertThat(c.invocationScheme()).isEqualTo("eudi-openid4vp");
        assertThat(c.responseMode()).isEqualTo(WalletProviderConfig.ResponseMode.DIRECT_POST_JWT);
        assertThat(c.requestUriMethod()).isEqualTo(WalletProviderConfig.RequestUriMethod.POST);
        assertThat(c.transactionTtlSeconds()).isEqualTo(240);
        assertThat(c.credentialFormats()).containsExactly("dc+sd-jwt", "mso_mdoc");
        assertThat(c.pid().sdJwtVcts()).containsExactly("urn:eudi:pid:1", "urn:eudi:pid:de:1");
        assertThat(c.pid().requestedClaims()).containsExactly("given_name", "family_name", "birthdate",
                "address.locality");
        assertThat(c.customCredentialQueries()).isEmpty();
        assertThat(c.trustAnchors()).contains("MIIC");
        assertThat(c.revocationChecking()).isEqualTo(TrustAnchors.RevocationMode.HARD_FAIL);
        assertThat(c.statusList().required()).isTrue();
        assertThat(c.statusList().onUnavailable()).isEqualTo(StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT);
        assertThat(c.statusList().maxCacheSeconds()).isEqualTo(600);
        assertThat(c.statusList().allowedHosts()).containsExactly("status.example.eu");
        assertThat(c.subject().strategy()).isEqualTo(WalletProviderConfig.Subject.Strategy.ATTRIBUTE_TUPLE);
        assertThat(c.subject().acknowledgeWeakSubject()).isTrue();
        assertThat(c.minimumLoa()).isEqualTo("http://eidas.europa.eu/LoA/substantial");
        assertThat(c.clockSkewSeconds()).isEqualTo(30);
        assertThat(c.allowLegacyVcSdJwtTyp()).isTrue();
        assertThat(c.limits().maxJwtBytes()).isEqualTo(32768);
        assertThat(c.limits().cborMaxDepth()).isEqualTo(8);
        assertThat(c.limits().cborMaxItems()).isEqualTo(10_000); // unset member keeps its default

        // YAML and stored config describe the same provider.
        assertThat(WalletProviderConfig.fromStored(c.toStored())).isEqualTo(c);
    }

    @Test
    void minimalYaml_getsTheDefaults() throws Exception {
        final WalletProviderConfig c = bind("""
                helix:
                  federation:
                    wallet:
                      - alias: w
                """).getWallet().get(0);
        assertThat(c).isEqualTo(WalletProviderConfig.fromStored(Map.of("alias", "w")));
        assertThat(c.clientIdScheme()).isEqualTo(WalletProviderConfig.ClientIdScheme.X509_HASH);
        assertThat(c.statusList().required()).isFalse();
        assertThat(c.pid().sdJwtVcts()).contains("urn:eudi:pid:1");
    }

    @Test
    void noWalletEntries_isAnEmptyList_andANullSetterIsGuarded() throws Exception {
        assertThat(bind("helix:\n  federation:\n    eid: []\n").getWallet()).isEmpty();
        final FederationProviderProperties p = new FederationProviderProperties();
        p.setWallet(null);
        assertThat(p.getWallet()).isNotNull().isEmpty();
    }
}
