/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.Pointer;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.Service;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.Spec;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.GRANTED;
import static io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.PID_TYPE;
import static io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.RECOGNISED;
import static io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.WITHDRAWN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link TrustedListLoader} on lists built and signed in the test: what counts as a current service, signature and
 * signer checks, the LOTL pointer chain, freshness, rollback, and the hostile-XML refusals.
 */
class TrustedListLoaderTest {

    static final String TL_URL = "https://tl.example/TL/UT.xml";
    static final String LOTL_URL = "https://lotl.example/lotl.xml";
    static final String NL_URL = "https://tl.example/TL/NL.xml";
    static final String DE_URL = "https://tl.example/TL/DE.xml";

    final TestPki.Leaf signer = TrustedListFixtures.signer("UT TL Signer");
    final TestPki.Leaf other = TrustedListFixtures.signer("Somebody Else");
    final X509Certificate issuerA = TestPki.create("PID Issuer A").root();
    final X509Certificate issuerB = TestPki.create("PID Issuer B").root();
    final Map<String, byte[]> served = new HashMap<>();
    final TrustedListFetcher fetcher = (url, realm) -> {
        final byte[] body = served.get(url);
        if (body == null) {
            throw new TrustedListException(TrustedListException.Kind.FETCH, "not found");
        }
        return body;
    };
    final TrustedListLoader loader = new TrustedListLoader(fetcher, Clock.systemUTC());

    static TrustedListSpec spec(final String url, final TestPki.Leaf... signers) {
        return TrustedListSpec.of(url, TrustedListSpec.Format.ETSI_119612_XML,
                java.util.Arrays.stream(signers).map(TestPki.Leaf::certificate).toList(), Set.of(PID_TYPE));
    }

    @Test
    void validList_yieldsTheCurrentServicesWithTheirMetadata() throws Exception {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT").sequence(12)
                .service(Service.granted("Issuer A", issuerA)), signer));

        final LoadedList loaded = loader.load(spec(TL_URL, signer), "realm");

        assertThat(loaded.services()).singleElement().satisfies(s -> {
            assertThat(s.certificate()).isEqualTo(issuerA);
            assertThat(s.serviceType()).isEqualTo(PID_TYPE);
            assertThat(s.serviceName()).isEqualTo("Issuer A PID issuance");
            assertThat(s.provider()).isEqualTo("Issuer A");
            assertThat(s.country()).isEqualTo("UT");
            assertThat(s.status()).isEqualTo(GRANTED);
        });
        assertThat(loaded.sequence()).isEqualTo(12);
        assertThat(loaded.nextUpdate()).isAfter(Instant.now());
        assertThat(loaded.issuedAt()).isBefore(Instant.now());
    }

    @Test
    void withdrawnService_isNotCurrent_andItsGrantedHistoryDoesNotCount() throws Exception {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA))
                .service(Service.granted("Issuer B", issuerB).withStatus(WITHDRAWN)), signer));

        assertThat(loader.load(spec(TL_URL, signer), "realm").services())
                .extracting(ListedService::certificate).containsExactly(issuerA);
    }

    @Test
    void recognisedAtNationalLevel_countsByDefault_butNotWhenOnlyGrantedIsAccepted() throws Exception {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer B", issuerB).withStatus(RECOGNISED)), signer));

        assertThat(loader.load(spec(TL_URL, signer), "realm").services()).hasSize(1);
        assertThat(loader.load(spec(TL_URL, signer).withAcceptedStatuses(Set.of(GRANTED)), "realm").services())
                .isEmpty();
    }

    @Test
    void serviceStartingInTheFuture_andOtherServiceTypes_areNotIncluded() throws Exception {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA).startingAt(Instant.now().plus(2, ChronoUnit.DAYS)))
                .service(Service.granted("Issuer B", issuerB).withType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")),
                signer));

        assertThat(loader.load(spec(TL_URL, signer), "realm").services()).isEmpty();
    }

    @Test
    void tamperedList_isRefused() {
        final String signed = new String(TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA)), signer), StandardCharsets.UTF_8);
        served.put(TL_URL, signed.replace("Issuer A PID issuance", "Issuer Z PID issuance")
                .getBytes(StandardCharsets.UTF_8));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE);
    }

    @Test
    void addedService_afterSigning_isRefused() {
        final String signed = new String(TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA)), signer), StandardCharsets.UTF_8);
        final String injected = signed.replace("</TSPServices>", "<TSPService><ServiceInformation>"
                + "<ServiceTypeIdentifier>" + PID_TYPE + "</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">x"
                + "</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>"
                + TrustedListFixtures.b64(issuerB) + "</X509Certificate></DigitalId></ServiceDigitalIdentity>"
                + "<ServiceStatus>" + GRANTED + "</ServiceStatus><StatusStartingTime>2020-01-01T00:00:00Z"
                + "</StatusStartingTime></ServiceInformation></TSPService></TSPServices>");
        served.put(TL_URL, injected.getBytes(StandardCharsets.UTF_8));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE);
    }

    @Test
    void listSignedByAnotherKey_isRefused_evenThoughItsKeyInfoNamesThatKey() {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA)), other));

        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE))
                .hasMessageContaining("does not verify with a configured signer");
    }

    @Test
    void anyOfSeveralPinnedSigners_verifies() throws Exception {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA)), signer));

        assertThat(loader.load(spec(TL_URL, other, signer), "realm").services()).hasSize(1);
    }

    @Test
    void unsignedList_isRefused() {
        served.put(TL_URL, TrustedListFixtures.xml(Spec.memberState("UT").service(Service.granted("A", issuerA)))
                .getBytes(StandardCharsets.UTF_8));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE);
    }

    @Test
    void signatureThatDoesNotCoverTheWholeList_isRefused() {
        // a valid signature over the SignedProperties only (no reference to the list root) proves nothing about it
        final String xml = TrustedListFixtures.xml(Spec.memberState("UT").service(Service.granted("A", issuerA)));
        final String signed = new String(TrustedListFixtures.sign(xml, signer), StandardCharsets.UTF_8);
        final String wrapped = signed.replace("URI=\"#TrustServiceStatusList\"", "URI=\"#elsewhere\"")
                .replace("<SchemeInformation>", "<SchemeInformation Id=\"elsewhere\">");
        served.put(TL_URL, wrapped.getBytes(StandardCharsets.UTF_8));

        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE))
                .hasMessageContaining("does not cover the whole list");
    }

    @Test
    void signerExpiredLongerAgoThanTheGrace_isRefused_evenForABackdatedList() {
        // the review's case: a key that expired 400 days ago signs a list backdated into its validity
        final Instant now = Instant.now();
        final TestPki.Leaf expired = TrustedListFixtures.signer("Expired", now.minus(800, ChronoUnit.DAYS),
                now.minus(400, ChronoUnit.DAYS));
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .issued(now.minus(401, ChronoUnit.DAYS)).nextUpdate(now.plus(30, ChronoUnit.DAYS))
                .service(Service.granted("Issuer A", issuerA)), expired));

        assertThat(assertKind(() -> loader.load(spec(TL_URL, expired), "realm"), TrustedListException.Kind.SIGNER))
                .hasMessageContaining("expired");
    }

    @Test
    void signerExpiredWithinTheGrace_isAccepted_likeTheCurrentEudiTestList() throws Exception {
        // the EUDI reference implementation's test LOTL: signer expired ~100 days ago, list issued while it was valid
        final Instant now = Instant.now();
        final TestPki.Leaf expired = TrustedListFixtures.signer("EUDI-like", now.minus(400, ChronoUnit.DAYS),
                now.minus(103, ChronoUnit.DAYS));
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .issued(now.minus(168, ChronoUnit.DAYS)).nextUpdate(now.plus(12, ChronoUnit.DAYS))
                .service(Service.granted("Issuer A", issuerA)), expired));

        assertThat(loader.load(spec(TL_URL, expired), "realm").services()).hasSize(1);
        assertKind(() -> new TrustedListLoader(fetcher, Clock.systemUTC(), SecureXml.DEFAULT_MAX_BYTES,
                new TrustedListLoader.Settings(java.time.Duration.ZERO)).load(spec(TL_URL, expired), "realm"),
                TrustedListException.Kind.SIGNER);
    }

    @Test
    void weakSignerKeyNamedByAListOfLists_isNotUsed() throws Exception {
        final TestPki.Leaf weak = weakRsaSigner();
        final TestPki.Leaf lotl = TrustedListFixtures.signer("LOTL");
        served.put(LOTL_URL, TrustedListFixtures.signedXml(Spec.lotl()
                .pointer(Pointer.memberState(NL_URL, "NL", weak.certificate())), lotl));
        served.put(NL_URL, TrustedListFixtures.sign(TrustedListFixtures.xml(Spec.memberState("NL")
                .service(Service.granted("NL", issuerA))), weak,
                org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                "http://www.w3.org/2001/04/xmlenc#sha256"));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotl), "realm");

        assertThat(loaded.members()).singleElement().satisfies(m -> {
            assertThat(m.loaded()).isFalse();
            assertThat(m.errorKind()).isEqualTo(TrustedListException.Kind.SIGNER);
        });
    }

    static TestPki.Leaf weakRsaSigner() throws Exception {
        final java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        final java.security.KeyPair kp = g.generateKeyPair();
        final org.bouncycastle.asn1.x500.X500Name n = new org.bouncycastle.asn1.x500.X500Name("CN=Weak RSA");
        final Instant now = Instant.now();
        final X509Certificate c = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(n, java.math.BigInteger.TEN,
                        java.util.Date.from(now.minus(1, ChronoUnit.DAYS)), java.util.Date.from(now.plus(9, ChronoUnit.DAYS)),
                        n, kp.getPublic()).build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                        "SHA256withRSA").build(kp.getPrivate())));
        return new TestPki.Leaf(c, kp.getPrivate(), List.of(c));
    }

    @Test
    void sha1ReferenceDigest_isRefused() {
        final String xml = TrustedListFixtures.xml(Spec.memberState("UT").service(Service.granted("Issuer A", issuerA)));
        served.put(TL_URL, TrustedListFixtures.sign(xml, signer,
                org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
                "http://www.w3.org/2000/09/xmldsig#sha1"));

        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE))
                .hasMessageContaining("digest");
    }

    @Test
    void sha384AndSha512ReferenceDigests_areAccepted() throws Exception {
        final String xml = TrustedListFixtures.xml(Spec.memberState("UT").service(Service.granted("Issuer A", issuerA)));
        for (final String digest : List.of("http://www.w3.org/2001/04/xmldsig-more#sha384",
                "http://www.w3.org/2001/04/xmlenc#sha512")) {
            served.put(TL_URL, TrustedListFixtures.sign(xml, signer,
                    org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, digest));
            assertThat(loader.load(spec(TL_URL, signer), "realm").services()).hasSize(1);
        }
    }

    @Test
    void ecdsaSha1Signature_andParameterisedRsaPss_areRefused() {
        final String xml = TrustedListFixtures.xml(Spec.memberState("UT").service(Service.granted("Issuer A", issuerA)));
        served.put(TL_URL, TrustedListFixtures.sign(xml, signer,
                org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1,
                "http://www.w3.org/2001/04/xmlenc#sha256"));
        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE))
                .hasMessageContaining("signature algorithm");
        // the generic RSASSA-PSS identifier takes its hash and salt from parameters: not accepted
        final String pss = new String(TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA)), signer), StandardCharsets.UTF_8)
                .replace("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                        "http://www.w3.org/2007/05/xmldsig-more#rsa-pss");
        served.put(TL_URL, pss.getBytes(StandardCharsets.UTF_8));
        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE))
                .hasMessageContaining("signature algorithm");
    }

    @Test
    void nextUpdateInThePast_isRefusedAsExpired() {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .nextUpdate(Instant.now().minus(1, ChronoUnit.HOURS))
                .service(Service.granted("Issuer A", issuerA)), signer));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.EXPIRED);
    }

    @Test
    void closedList_withoutNextUpdate_isRefused() {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT").nextUpdate(null)
                .service(Service.granted("Issuer A", issuerA)), signer));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.EXPIRED);
    }

    @Test
    void lowerSequenceNumberThanTheLastGoodList_isRefusedAsRollback() {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT").sequence(4)
                .service(Service.granted("Issuer A", issuerA)), signer));

        assertKind(() -> loader.load(spec(TL_URL, signer).withPreviousSequence(5L), "realm"),
                TrustedListException.Kind.ROLLBACK);
    }

    @Test
    void signerCertificateNotValidWhenTheListWasIssued_isRefused() {
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .issued(Instant.now().minus(400, ChronoUnit.DAYS))
                .service(Service.granted("Issuer A", issuerA)), signer));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNER);
    }

    // ------------------------------------------------------------------------------------------------ LOTL chain

    final TestPki.Leaf lotlSigner = TrustedListFixtures.signer("LOTL Signer");
    final TestPki.Leaf nlSigner = TrustedListFixtures.signer("NL TL Signer");
    final TestPki.Leaf deSigner = TrustedListFixtures.signer("DE TL Signer");

    static LoadedList.Member member(final LoadedList loaded, final String territory) {
        return loaded.members().stream().filter(m -> territory.equals(m.territory())).findFirst().orElseThrow();
    }

    void serveLotl(final Pointer... pointers) {
        final Spec spec = Spec.lotl().sequence(300);
        for (final Pointer p : pointers) {
            spec.pointer(p);
        }
        served.put(LOTL_URL, TrustedListFixtures.signedXml(spec, lotlSigner));
    }

    @Test
    void lotl_followsItsPointers_verifyingEachListWithTheSignerTheLotlNames() throws Exception {
        serveLotl(new Pointer(LOTL_URL, TrustedListFixtures.LOTL_TYPE, "EU", "application/vnd.etsi.tsl+xml",
                        List.of(lotlSigner.certificate())),
                new Pointer("https://tl.example/TL/NL.pdf", TrustedListFixtures.GENERIC_TYPE, "NL",
                        "application/pdf", List.of(nlSigner.certificate())),
                Pointer.memberState(NL_URL, "NL", nlSigner.certificate()),
                Pointer.memberState(DE_URL, "DE", deSigner.certificate()));
        served.put(NL_URL, TrustedListFixtures.signedXml(Spec.memberState("NL").sequence(11).nextUpdate(
                Instant.now().plus(5, ChronoUnit.DAYS)).service(Service.granted("NL Issuer", issuerA)), nlSigner));
        served.put(DE_URL, TrustedListFixtures.signedXml(Spec.memberState("DE")
                .service(Service.granted("DE Issuer", issuerB)), deSigner));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotlSigner), "realm");

        assertThat(loaded.services()).extracting(ListedService::country).containsExactlyInAnyOrder("NL", "DE");
        assertThat(loaded.listsRead()).isEqualTo(3);
        assertThat(loaded.sequence()).isEqualTo(300);
        assertThat(loaded.members()).hasSize(2).allMatch(LoadedList.Member::loaded);
        // each member keeps its own NextUpdate and sequence
        assertThat(member(loaded, "NL").sequence()).isEqualTo(11);
        assertThat(member(loaded, "NL").nextUpdate()).isBefore(Instant.now().plus(6, ChronoUnit.DAYS));
        assertThat(member(loaded, "DE").nextUpdate()).isAfter(Instant.now().plus(20, ChronoUnit.DAYS));
        assertThat(member(loaded, "NL").key()).isEqualTo(LoadedList.Member.key(NL_URL, "NL"));
    }

    @Test
    void lotl_memberSignedByAKeyTheLotlDoesNotName_isRefused_withoutBlockingTheOthers() throws Exception {
        serveLotl(Pointer.memberState(NL_URL, "NL", nlSigner.certificate()),
                Pointer.memberState(DE_URL, "DE", deSigner.certificate()));
        // signed by the LOTL's own key: valid XMLDSig, but not the key the LOTL names for NL
        served.put(NL_URL, TrustedListFixtures.signedXml(Spec.memberState("NL")
                .service(Service.granted("NL Issuer", issuerA)), lotlSigner));
        served.put(DE_URL, TrustedListFixtures.signedXml(Spec.memberState("DE")
                .service(Service.granted("DE Issuer", issuerB)), deSigner));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotlSigner), "realm");

        assertThat(member(loaded, "NL").loaded()).isFalse();
        assertThat(member(loaded, "NL").errorKind()).isEqualTo(TrustedListException.Kind.SIGNATURE);
        assertThat(member(loaded, "DE").loaded()).isTrue();
        assertThat(loaded.services()).extracting(ListedService::certificate).containsExactly(issuerB);
    }

    @Test
    void lotl_memberReplayWithALowerSequence_isRefused() throws Exception {
        serveLotl(Pointer.memberState(NL_URL, "NL", nlSigner.certificate()));
        served.put(NL_URL, TrustedListFixtures.signedXml(Spec.memberState("NL").sequence(3)
                .service(Service.granted("NL Issuer", issuerA)), nlSigner));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotlSigner)
                .withPreviousMemberSequences(Map.of(LoadedList.Member.key(NL_URL, "NL"), 9L)), "realm");

        assertThat(member(loaded, "NL").loaded()).isFalse();
        assertThat(member(loaded, "NL").errorKind()).isEqualTo(TrustedListException.Kind.ROLLBACK);
        assertThat(loaded.services()).isEmpty();
    }

    @Test
    void lotl_memberWhoseTerritoryOrTypeDiffersFromThePointer_isRefused() throws Exception {
        serveLotl(Pointer.memberState(NL_URL, "NL", nlSigner.certificate()),
                new Pointer(DE_URL, "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", "DE",
                        "application/vnd.etsi.tsl+xml", List.of(deSigner.certificate())));
        served.put(NL_URL, TrustedListFixtures.signedXml(Spec.memberState("FR")
                .service(Service.granted("FR Issuer", issuerA)), nlSigner));
        final Spec otherType = Spec.memberState("DE").service(Service.granted("DE Issuer", issuerB));
        served.put(DE_URL, TrustedListFixtures.sign(TrustedListFixtures.xml(otherType).replace(
                "TSLType/EUgeneric", "TSLType/CClist"), deSigner));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotlSigner), "realm");

        assertThat(member(loaded, "NL").errorKind()).isEqualTo(TrustedListException.Kind.MALFORMED);
        assertThat(member(loaded, "NL").errorMessage()).contains("territory");
        assertThat(member(loaded, "DE").errorKind()).isEqualTo(TrustedListException.Kind.MALFORMED);
        assertThat(member(loaded, "DE").errorMessage()).contains("type");
        assertThat(loaded.services()).isEmpty();
    }

    @Test
    void lotl_territoryFilter_readsOnlyTheChosenLists() throws Exception {
        serveLotl(Pointer.memberState(NL_URL, "NL", nlSigner.certificate()),
                Pointer.memberState(DE_URL, "DE", nlSigner.certificate()));
        served.put(NL_URL, TrustedListFixtures.signedXml(Spec.memberState("NL")
                .service(Service.granted("NL Issuer", issuerA)), nlSigner));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotlSigner).withTerritories(Set.of("NL")), "realm");

        assertThat(loaded.services()).extracting(ListedService::country).containsExactly("NL");
        assertThat(loaded.members()).extracting(LoadedList.Member::territory).containsExactly("NL");
    }

    @Test
    void lotl_plainHttpPointer_isSkippedAndReported_theOthersLoad() throws Exception {
        serveLotl(Pointer.memberState("http://tl.example/TL/SK.xml", "SK", signer.certificate()),
                Pointer.memberState(NL_URL, "NL", nlSigner.certificate()));
        served.put(NL_URL, TrustedListFixtures.signedXml(Spec.memberState("NL")
                .service(Service.granted("NL Issuer", issuerA)), nlSigner));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotlSigner), "realm");

        assertThat(member(loaded, "SK").loaded()).isFalse();
        assertThat(member(loaded, "SK").errorKind()).isEqualTo(TrustedListException.Kind.POLICY);
        assertThat(member(loaded, "NL").loaded()).isTrue();
    }

    @Test
    void lotl_expiredMember_failsAlone() throws Exception {
        serveLotl(Pointer.memberState(NL_URL, "NL", nlSigner.certificate()),
                Pointer.memberState(DE_URL, "DE", deSigner.certificate()));
        served.put(NL_URL, TrustedListFixtures.signedXml(Spec.memberState("NL").nextUpdate(
                Instant.now().minus(1, ChronoUnit.HOURS)).service(Service.granted("NL Issuer", issuerA)), nlSigner));
        served.put(DE_URL, TrustedListFixtures.signedXml(Spec.memberState("DE")
                .service(Service.granted("DE Issuer", issuerB)), deSigner));

        final LoadedList loaded = loader.load(spec(LOTL_URL, lotlSigner), "realm");

        assertThat(member(loaded, "NL").errorKind()).isEqualTo(TrustedListException.Kind.EXPIRED);
        assertThat(member(loaded, "DE").loaded()).isTrue();
    }

    // ------------------------------------------------------------------------------------------------ hostile XML

    @Test
    void doctype_andExternalEntities_areRefusedBeforeAnythingIsResolved() {
        final String xxe = "<?xml version=\"1.0\"?><!DOCTYPE TrustServiceStatusList [<!ENTITY x SYSTEM "
                + "\"file:///etc/passwd\">]><TrustServiceStatusList xmlns=\"" + TrustedListFixtures.TSL_NS
                + "\">&x;</TrustServiceStatusList>";
        served.put(TL_URL, xxe.getBytes(StandardCharsets.UTF_8));

        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.MALFORMED))
                .hasMessageNotContaining("passwd");
    }

    @Test
    void billionLaughs_isRefused() {
        final String bomb = "<?xml version=\"1.0\"?><!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;"
                + "&a;&a;&a;&a;\">]><l>&b;</l>";
        served.put(TL_URL, bomb.getBytes(StandardCharsets.UTF_8));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.MALFORMED);
    }

    @Test
    void xinclude_isNotProcessed() {
        final String xi = "<?xml version=\"1.0\"?><TrustServiceStatusList xmlns=\"" + TrustedListFixtures.TSL_NS
                + "\" xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" "
                + "parse=\"text\"/></TrustServiceStatusList>";
        served.put(TL_URL, xi.getBytes(StandardCharsets.UTF_8));

        // parsed without inclusion, then refused as unsigned
        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE))
                .hasMessageContaining("not signed");
    }

    @Test
    void deeplyNestedDocument_isRefused() {
        final StringBuilder sb = new StringBuilder("<?xml version=\"1.0\"?>");
        sb.append("<a>".repeat(SecureXml.MAX_DEPTH + 5)).append("</a>".repeat(SecureXml.MAX_DEPTH + 5));
        served.put(TL_URL, sb.toString().getBytes(StandardCharsets.UTF_8));

        assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.MALFORMED);
    }

    @Test
    void oversizedDocument_isRefusedByTheParserToo() {
        final byte[] big = new byte[(int) (SecureXml.DEFAULT_MAX_BYTES + 1)];
        java.util.Arrays.fill(big, (byte) ' ');
        assertThatThrownBy(() -> SecureXml.parse(big, SecureXml.DEFAULT_MAX_BYTES))
                .isInstanceOfSatisfying(TrustedListException.class,
                        e -> assertThat(e.kind()).isEqualTo(TrustedListException.Kind.TOO_LARGE));
    }

    @Test
    void duplicateIds_areRefused() {
        final String signed = new String(TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA)), signer), StandardCharsets.UTF_8);
        served.put(TL_URL, signed.replace("<SchemeInformation>", "<SchemeInformation Id=\"TrustServiceStatusList\">")
                .getBytes(StandardCharsets.UTF_8));

        assertThat(assertKind(() -> loader.load(spec(TL_URL, signer), "realm"), TrustedListException.Kind.SIGNATURE))
                .hasMessageContaining("duplicate Id");
    }

    // ------------------------------------------------------------------------------------------------ LoTE JSON

    @Test
    void loteJson_valid_yieldsItsEntities() throws Exception {
        served.put(TL_URL, TrustedListFixtures.signedLote(TrustedListFixtures.loteJson(9,
                Instant.now().plus(90, ChronoUnit.DAYS), List.of(
                        TrustedListFixtures.LoteEntity.pid("Bundesdruckerei", "DE", issuerA))), signer));

        final LoadedList loaded = loader.load(TrustedListSpec.of(TL_URL, TrustedListSpec.Format.ETSI_119602_JSON,
                List.of(signer.certificate()), Set.of(TrustedListFixtures.LOTE_PID_TYPE)), "realm");

        assertThat(loaded.services()).singleElement().satisfies(s -> {
            assertThat(s.certificate()).isEqualTo(issuerA);
            assertThat(s.provider()).isEqualTo("Bundesdruckerei");
            assertThat(s.country()).isEqualTo("DE");
            assertThat(s.serviceName()).isEqualTo("Bundesdruckerei PID");
        });
        assertThat(loaded.sequence()).isEqualTo(9);
    }

    @Test
    void loteJson_signedByAnotherKey_isRefused() {
        served.put(TL_URL, TrustedListFixtures.signedLote(TrustedListFixtures.loteJson(9,
                Instant.now().plus(90, ChronoUnit.DAYS), List.of()), other));

        assertKind(() -> loader.load(TrustedListSpec.of(TL_URL, TrustedListSpec.Format.ETSI_119602_JSON,
                List.of(signer.certificate()), Set.of(TrustedListFixtures.LOTE_PID_TYPE)), "realm"),
                TrustedListException.Kind.SIGNATURE);
    }

    @Test
    void loteJson_unsignedOrAlgNone_isRefused() {
        final String json = TrustedListFixtures.loteJson(9, Instant.now().plus(90, ChronoUnit.DAYS), List.of());
        final String none = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8))
                + ".";
        served.put(TL_URL, none.getBytes(StandardCharsets.US_ASCII));
        served.put(NL_URL, json.getBytes(StandardCharsets.UTF_8));
        final TrustedListSpec lote = TrustedListSpec.of(TL_URL, TrustedListSpec.Format.ETSI_119602_JSON,
                List.of(signer.certificate()), Set.of(TrustedListFixtures.LOTE_PID_TYPE));

        assertKind(() -> loader.load(lote, "realm"), TrustedListException.Kind.SIGNATURE);
        assertKind(() -> loader.load(TrustedListSpec.of(NL_URL, TrustedListSpec.Format.ETSI_119602_JSON,
                List.of(signer.certificate()), Set.of(TrustedListFixtures.LOTE_PID_TYPE)), "realm"),
                TrustedListException.Kind.SIGNATURE);
    }

    @Test
    void loteJson_pastNextUpdate_isRefusedAsExpired() {
        served.put(TL_URL, TrustedListFixtures.signedLote(TrustedListFixtures.loteJson(9,
                Instant.now().minus(1, ChronoUnit.DAYS), List.of()), signer));

        assertKind(() -> loader.load(TrustedListSpec.of(TL_URL, TrustedListSpec.Format.ETSI_119602_JSON,
                List.of(signer.certificate()), Set.of(TrustedListFixtures.LOTE_PID_TYPE)), "realm"),
                TrustedListException.Kind.EXPIRED);
    }

    @Test
    void clockIsTheLoadersClock() {
        final Clock future = Clock.fixed(Instant.now().plus(60, ChronoUnit.DAYS), ZoneOffset.UTC);
        served.put(TL_URL, TrustedListFixtures.signedXml(Spec.memberState("UT")
                .service(Service.granted("Issuer A", issuerA)), signer));

        assertKind(() -> new TrustedListLoader(fetcher, future).load(spec(TL_URL, signer), "realm"),
                TrustedListException.Kind.EXPIRED);
    }

    interface Call {
        Object run() throws Exception;
    }

    static TrustedListException assertKind(final Call call, final TrustedListException.Kind kind) {
        final TrustedListException[] caught = new TrustedListException[1];
        assertThatThrownBy(call::run).isInstanceOfSatisfying(TrustedListException.class, e -> {
            assertThat(e.kind()).as(e.getMessage()).isEqualTo(kind);
            caught[0] = e;
        });
        return caught[0];
    }
}
