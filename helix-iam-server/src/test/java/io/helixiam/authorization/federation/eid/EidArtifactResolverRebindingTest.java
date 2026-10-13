/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * M6: the eID back-channel ArtifactResolve (SOAP, mutual TLS when an SP key is configured) goes to the address the
 * guard validated. The resolver checks the ARS URL up front (before signing anything) and the POST resolves once more
 * through the guard and connects to what that resolution validated: two lookups, never a third.
 */
class EidArtifactResolverRebindingTest {

    private static EidProviderConfig config(final String arsUrl) throws Exception {
        final java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final java.security.KeyPair sp = kpg.generateKeyPair();
        final long now = System.currentTimeMillis();
        final org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name("CN=HelixSP");
        final java.security.cert.X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name,
                        java.math.BigInteger.valueOf(now), new java.util.Date(now - 60_000),
                        new java.util.Date(now + 86_400_000L), name, sp.getPublic())
                        .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                                .build(sp.getPrivate())));
        final java.util.Base64.Encoder b64 = java.util.Base64.getMimeEncoder(64, new byte[] {'\n'});
        final String keyPem = "-----BEGIN PRIVATE KEY-----\n" + b64.encodeToString(sp.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        final String certPem = "-----BEGIN CERTIFICATE-----\n" + b64.encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        return new EidProviderConfig(EidScheme.DIGID, "digid", "DigiD", "https://digid.example/sso",
                "https://digid.example/idp", "https://helix.test/sp", "https://helix.test/acs", null, null,
                keyPem, certPem, null, null, EidProviderConfig.Binding.POST, null,
                EidProviderConfig.ResponseBinding.ARTIFACT, arsUrl);
    }

    @Test
    void theArtifactResolveIsPostedToTheValidatedAddressOnly() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("ars.rebind.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "text/xml", "<not-soap/>"));
            final OpenSamlEidArtifactResolver resolver = new OpenSamlEidArtifactResolver(target.guard(2));

            final EidProviderConfig config = config(target.url("http", "/ars"));
            assertThatThrownBy(() -> resolver.resolve(config, "art-1"))
                    .isInstanceOf(IllegalStateException.class); // the junk answer is refused after the POST

            assertThat(target.requests()).hasSize(1);
            final RebindingTarget.Seen seen = target.requests().get(0);
            assertThat(seen.method()).isEqualTo("POST");
            assertThat(seen.header("SOAPAction")).isEqualTo("http://www.oasis-open.org/committees/security");
            assertThat(seen.body()).contains("ArtifactResolve").contains("art-1");
            assertThat(target.lookups()).isEqualTo(2);
        }
    }

    @Test
    void anArsHostThatRebindsAfterTheUpFrontCheckIsNeverContacted() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("ars.rebind.test")) {
            final OpenSamlEidArtifactResolver resolver = new OpenSamlEidArtifactResolver(target.guard(1));

            final EidProviderConfig config = config(target.url("http", "/ars"));
            assertThatThrownBy(() -> resolver.resolve(config, "art-1")).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("blocked");
            assertThat(target.requests()).isEmpty();
            assertThat(target.lookups()).isEqualTo(2);
        }
    }
}
