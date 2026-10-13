/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Production readiness item 7: the mdoc decoding path against DeviceResponses we did not make. The vectors are
 * {@code vp_token}s produced by the EU Digital Identity Wallet reference implementation (an mDL signed by the "EU Digital
 * Identity Wallet Test CA", and a three-document response: two PIDs from the reference PID issuer and an mDL with a
 * portrait), as published in the EU reference verifier's tests (Apache-2.0; source, commit and licence in
 * {@code wallet/vectors/SOURCES.md}). That verifier asserts both are valid when chain trust and validity dates are not
 * checked; we check the same with our own code, independently:
 * <ul>
 *   <li>{@link StrictCbor} decodes the whole DeviceResponse (definite lengths, tag 24, tag 1004 / tag 0 dates);</li>
 *   <li>{@link CoseSign1} decodes each IssuerAuth and its signature verifies with the leaf of its own {@code x5chain};
 *       one flipped signature bit does not;</li>
 *   <li>{@link MobileSecurityObject} decodes each MSO (docType, digest algorithm, device key), and every
 *       IssuerSignedItemBytes, hashed exactly as received, equals its {@code valueDigests} entry.</li>
 * </ul>
 * The DeviceAuth ({@code deviceSignature}) of these responses cannot be verified: the SessionTranscript they were signed
 * over is not published with them. It is checked for shape only (a detached COSE_Sign1, ES256). Our DeviceAuthentication
 * construction stays covered by the OpenID4VP B.2.6.1 transcript vector and the TestWallet round trips.
 */
class EudiReferenceDeviceResponseVectorTest {

    private static final String MDL = "org.iso.18013.5.1.mDL";
    private static final String PID = "eu.europa.ec.eudi.pid.1";


    static Stream<Arguments> documents() throws IOException {
        final List<Arguments> all = new ArrayList<>();
        for (final String file : List.of("eudi-ref-mdl-device-response.b64u",
                "eudi-ref-three-document-device-response.b64u")) {
            final List<CborValue> docs = documentsOf(deviceResponse(file));
            for (int i = 0; i < docs.size(); i++) {
                all.add(Arguments.of(file + "#" + i, docs.get(i)));
            }
        }
        return all.stream();
    }

    static byte[] load(final String file) throws IOException {
        try (InputStream in = EudiReferenceDeviceResponseVectorTest.class
                .getResourceAsStream("/wallet/vectors/mdoc/" + file)) {
            assertThat(in).as(file).isNotNull();
            final String body = new String(in.readAllBytes(), StandardCharsets.US_ASCII).lines()
                    .filter(line -> !line.startsWith("#")).collect(Collectors.joining()).trim();
            return Base64.getUrlDecoder().decode(body);
        }
    }

    static CborValue.Dict deviceResponse(final String file) throws IOException {
        return (CborValue.Dict) StrictCbor.decode(load(file));
    }

    private static List<CborValue> documentsOf(final CborValue.Dict response) {
        return ((CborValue.Array) response.get("documents").orElseThrow()).items();
    }

    private static String text(final CborValue.Dict map, final String key) {
        return ((CborValue.Text) map.get(key).orElseThrow()).value();
    }

    @Test
    void theResponses_decode_withTheDocumentsTheReferenceVerifierReports() throws IOException {
        final CborValue.Dict mdl = deviceResponse("eudi-ref-mdl-device-response.b64u");
        assertThat(text(mdl, "version")).isEqualTo("1.0");
        assertThat(documentsOf(mdl)).extracting(d -> text((CborValue.Dict) d, "docType")).containsExactly(MDL);
        assertThat(mdl.get("status")).contains(new CborValue.Int(0));

        final CborValue.Dict three = deviceResponse("eudi-ref-three-document-device-response.b64u");
        assertThat(documentsOf(three)).extracting(d -> text((CborValue.Dict) d, "docType"))
                .containsExactly(PID, PID, MDL);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("documents")
    void issuerAuth_verifiesWithItsOwnX5chainLeaf_andATamperedSignatureDoesNot(final String name,
                                                                              final CborValue document) {
        final CoseSign1 issuerAuth = issuerAuth((CborValue.Dict) document);

        assertThat(issuerAuth.algorithm()).isEqualTo(CoseSign1.ES256);
        final List<X509Certificate> chain = issuerAuth.x5chain();
        assertThat(chain).as(name).isNotEmpty();
        assertThat(issuerAuth.payload()).as("attached MSO").isNotNull();
        assertThat(issuerAuth.verify(chain.get(0).getPublicKey(), null)).as(name).isTrue();

        final byte[] signature = issuerAuth.signature();
        signature[signature.length - 1] ^= 0x01;
        final CoseSign1 tampered = new CoseSign1(issuerAuth.protectedHeader(), issuerAuth.unprotectedHeader(),
                issuerAuth.payload(), signature);
        assertThat(tampered.verify(chain.get(0).getPublicKey(), null)).isFalse();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("documents")
    void theMso_decodes_andEveryIssuerSignedItemMatchesItsDigest(final String name, final CborValue document)
            throws Exception {
        final CborValue.Dict doc = (CborValue.Dict) document;
        final MobileSecurityObject mso = MobileSecurityObject.decode(issuerAuth(doc).payload());

        assertThat(mso.docType()).isEqualTo(text(doc, "docType"));
        assertThat(mso.digestAlgorithm()).isEqualTo("SHA-256");
        assertThat(mso.deviceKey().getAlgorithm()).isEqualTo("EC");
        final CborValue.Dict nameSpaces = (CborValue.Dict) ((CborValue.Dict) doc.get("issuerSigned").orElseThrow())
                .get("nameSpaces").orElseThrow();
        int checked = 0;
        for (final Map.Entry<CborValue, CborValue> ns : nameSpaces.entries().entrySet()) {
            final String namespace = ((CborValue.Text) ns.getKey()).value();
            for (final CborValue value : ((CborValue.Array) ns.getValue()).items()) {
                final CborValue.Embedded item = (CborValue.Embedded) value;
                final CborValue.Dict decoded = (CborValue.Dict) StrictCbor.decode(item.content());
                final int digestId = (int) ((CborValue.Int) decoded.get("digestID").orElseThrow()).value();
                assertThat(MessageDigest.getInstance("SHA-256").digest(item.encoded()))
                        .as(name + " " + namespace + "/" + digestId)
                        .isEqualTo(mso.valueDigests().get(namespace).get(digestId));
                checked++;
            }
        }
        assertThat(checked).as(name).isPositive();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("documents")
    void deviceAuth_isADetachedEs256DeviceSignature(final String name, final CborValue document) {
        final CborValue.Dict deviceSigned = (CborValue.Dict) ((CborValue.Dict) document).get("deviceSigned")
                .orElseThrow();
        final CborValue.Dict deviceAuth = (CborValue.Dict) deviceSigned.get("deviceAuth").orElseThrow();
        assertThat(deviceAuth.get("deviceMac")).isEmpty();

        final CoseSign1 deviceSignature = CoseSign1.decode(deviceAuth.get("deviceSignature").orElseThrow());

        assertThat(deviceSignature.payload()).as(name + ": detached").isNull();
        assertThat(deviceSignature.algorithm()).isEqualTo(CoseSign1.ES256);
        assertThat(deviceSigned.get("nameSpaces").orElseThrow()).isInstanceOf(CborValue.Embedded.class);
    }

    @Test
    void theMdlCarriesTheValuesTheIssuerSigned() throws Exception {
        final CborValue.Dict doc = (CborValue.Dict) documentsOf(deviceResponse("eudi-ref-mdl-device-response.b64u"))
                .get(0);
        final CborValue.Dict nameSpaces = (CborValue.Dict) ((CborValue.Dict) doc.get("issuerSigned").orElseThrow())
                .get("nameSpaces").orElseThrow();
        final Map<String, CborValue> elements = new java.util.HashMap<>();
        for (final CborValue value : ((CborValue.Array) nameSpaces.get("org.iso.18013.5.1").orElseThrow()).items()) {
            final CborValue.Dict item = (CborValue.Dict) StrictCbor.decode(((CborValue.Embedded) value).content());
            elements.put(text(item, "elementIdentifier"), item.get("elementValue").orElseThrow());
        }

        assertThat(elements.get("family_name")).isEqualTo(new CborValue.Text("ANDERSSON"));
        assertThat(elements.get("given_name")).isEqualTo(new CborValue.Text("JAN"));
        assertThat(elements.get("birth_date")).isEqualTo(new CborValue.Tagged(1004, new CborValue.Text("1985-03-30")));
    }

    /**
     * Interop finding, accepted by maintainer ruling: the reference issuer wrote this mDL's device key with a 31-byte
     * {@code x} (a leading zero octet dropped; RFC 9053 §7.1.1 asks for the full field length). {@link MobileSecurityObject}
     * left-pads it to 32 bytes, so it is the same point, still checked to be on the curve; its digests are checked with
     * every other document above.
     */
    @Test
    void aDeviceKey_withA31ByteX_isAcceptedAfterLeftPadding() throws Exception {
        final CborValue.Dict doc = (CborValue.Dict) documentsOf(
                deviceResponse("eudi-ref-three-document-device-response.b64u")).get(2);
        final byte[] payload = issuerAuth(doc).payload();
        final CborValue.Dict raw = (CborValue.Dict) StrictCbor.decode(
                ((CborValue.Embedded) StrictCbor.decode(payload)).content());
        final CborValue.Dict deviceKey = (CborValue.Dict) ((CborValue.Dict) raw.get("deviceKeyInfo").orElseThrow())
                .get("deviceKey").orElseThrow();
        final byte[] shortX = ((CborValue.Bytes) deviceKey.get(-2).orElseThrow()).value();
        assertThat(shortX).hasSize(31);

        final java.security.interfaces.ECPublicKey key =
                (java.security.interfaces.ECPublicKey) MobileSecurityObject.decode(payload).deviceKey();

        assertThat(key.getW().getAffineX()).isEqualTo(new java.math.BigInteger(1, shortX));
        assertThat(key.getW().getAffineY())
                .isEqualTo(new java.math.BigInteger(1, ((CborValue.Bytes) deviceKey.get(-3).orElseThrow()).value()));
    }

    private static CoseSign1 issuerAuth(final CborValue.Dict document) {
        final CborValue.Dict issuerSigned = (CborValue.Dict) document.get("issuerSigned").orElseThrow();
        return CoseSign1.decode(issuerSigned.get("issuerAuth").orElseThrow());
    }
}
