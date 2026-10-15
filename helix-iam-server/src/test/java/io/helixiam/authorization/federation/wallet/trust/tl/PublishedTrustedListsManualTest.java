/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import com.nimbusds.jose.JWSObject;
import io.helixiam.common.net.OutboundUrlGuard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Opt-in, never in CI ({@code -Dhelix.tl.live=true}): fetches the real published lists over the production transport
 * and verifies them with the production loader. The signer pins here are taken from the fetched lists themselves
 * (trust on first use) because the point is to prove the format and signature machinery against real XAdES/JAdES
 * output, not to establish trust; an operator pins the signer certificates from the publisher (the Official Journal
 * for the EU LOTL).
 *
 * <pre>mvn -Dtest=PublishedTrustedListsManualTest -Dhelix.tl.live=true test</pre>
 */
@EnabledIfSystemProperty(named = "helix.tl.live", matches = "true")
class PublishedTrustedListsManualTest {

    static final String EUDI_TEST_LOTL = "https://trustedlist.serviceproviders.eudiw.dev/LOTL/01.xml";
    static final String EU_LOTL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
    static final String EC_PID_LOTE = "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json";

    final TrustedListFetcher fetcher = new PinnedTrustedListFetcher(new OutboundUrlGuard(false), defaultTls(),
            SecureXml.DEFAULT_MAX_BYTES);
    final TrustedListLoader loader = new TrustedListLoader(fetcher, Clock.systemUTC());

    @Test
    void eudiReferenceImplementationTestLotl_pidProviders() throws Exception {
        final List<X509Certificate> pin = keyInfoCertificates(fetcher.fetch(EUDI_TEST_LOTL, "manual"));
        final LoadedList loaded = loader.load(TrustedListSpec.of(EUDI_TEST_LOTL, TrustedListSpec.Format.ETSI_119612_XML,
                pin, Set.of("http://uri.etsi.org/Svc/Svctype/Provider/PID")), "manual");
        report("EUDI test LOTL (PID providers)", loaded);
        assertThat(loaded.services()).isNotEmpty();
    }

    @Test
    void euLotl_qualifiedCaServicesOfThreeMemberStates() throws Exception {
        final byte[] body = fetcher.fetch(EU_LOTL, "manual");
        final List<X509Certificate> pin = selfPointerCertificates(body);
        final LoadedList loaded = loader.load(TrustedListSpec.of(EU_LOTL, TrustedListSpec.Format.ETSI_119612_XML, pin,
                Set.of("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")).withTerritories(Set.of("NL", "AT", "LU")),
                "manual");
        report("EU LOTL -> NL/AT/LU (CA/QC)", loaded);
        assertThat(loaded.listsRead()).isEqualTo(4);
    }

    @Test
    void ecAcceptancePidProvidersLote() throws Exception {
        final byte[] body = fetcher.fetch(EC_PID_LOTE, "manual");
        final JWSObject jws = JWSObject.parse(new String(body, StandardCharsets.US_ASCII).trim());
        final X509Certificate pin = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(jws.getHeader().getX509CertChain().get(0).decode()));
        final LoadedList loaded = loader.load(TrustedListSpec.of(EC_PID_LOTE, TrustedListSpec.Format.ETSI_119602_JSON,
                List.of(pin), Set.of("http://uri.etsi.org/19602/SvcType/PID/Issuance")), "manual");
        report("EC acceptance LoTE (PID issuance)", loaded);
        assertThat(loaded.services()).isNotEmpty();
    }

    private static void report(final String what, final LoadedList loaded) {
        System.out.printf("%s: lists=%d services=%d sequence=%d issued=%s nextUpdate=%s%n", what, loaded.listsRead(),
                loaded.services().size(), loaded.sequence(), loaded.issuedAt(), loaded.nextUpdate());
        loaded.services().stream().limit(8).forEach(s -> System.out.printf("  %s | %s | %s%n", s.country(),
                s.provider(), s.certificate().getSubjectX500Principal().getName()));
    }

    private static List<X509Certificate> keyInfoCertificates(final byte[] body) throws Exception {
        final Element root = SecureXml.parse(body, SecureXml.DEFAULT_MAX_BYTES).getDocumentElement();
        return certificates(root.getElementsByTagNameNS(XmlListSignature.DSIG_NS, "X509Certificate"));
    }

    /** The certificates the LOTL's pointer to itself announces (the LOTL signers). */
    private static List<X509Certificate> selfPointerCertificates(final byte[] body) throws Exception {
        final Element root = SecureXml.parse(body, SecureXml.DEFAULT_MAX_BYTES).getDocumentElement();
        final NodeList pointers = root.getElementsByTagNameNS(Etsi119612List.TSL_NS, "OtherTSLPointer");
        for (int i = 0; i < pointers.getLength(); i++) {
            final Element p = (Element) pointers.item(i);
            if (p.getElementsByTagNameNS(Etsi119612List.TSL_NS, "TSLLocation").item(0).getTextContent().trim()
                    .equals(EU_LOTL)) {
                return certificates(p.getElementsByTagNameNS(Etsi119612List.TSL_NS, "X509Certificate"));
            }
        }
        throw new IllegalStateException("no self pointer");
    }

    private static List<X509Certificate> certificates(final NodeList nodes) throws Exception {
        final List<X509Certificate> out = new ArrayList<>();
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < nodes.getLength(); i++) {
            out.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                    Base64.getMimeDecoder().decode(nodes.item(i).getTextContent()))));
        }
        return out;
    }

    private static SSLContext defaultTls() {
        try {
            return SSLContext.getDefault();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
