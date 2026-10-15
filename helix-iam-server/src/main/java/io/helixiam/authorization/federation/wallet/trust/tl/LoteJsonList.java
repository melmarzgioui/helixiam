/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * An ETSI TS 119 602 V1.1.1 List of Trusted Entities in its JSON binding, as the European Commission publishes the EUDI
 * Wallet lists (for example {@code lists/eudiw/pid-providers.json}): a JWS compact serialization (JAdES baseline) whose
 * payload is {@code {"LoTE": {...}}}. The signature must verify with a pinned signer's key; the {@code x5c} in the
 * header is never trusted. Allowed: RS/PS/ES 256/384/512. Refused: {@code alg=none} (not a JWS), an unprotected or
 * detached payload ({@code b64=false}, {@code sigD}), and any {@code crit} parameter other than the JAdES ones that do
 * not change what is signed.
 *
 * <p>A LoTE has no per-service status in the PID provider list (its {@code StatusDeterminationApproach} makes listing
 * itself the trust decision); a service that does carry a {@code ServiceStatus} ending in {@code withdrawn} or
 * {@code deprecated...} is not current. Pointers to other LoTEs are not followed.
 */
final class LoteJsonList {

    private static final Set<JWSAlgorithm> ALLOWED = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384,
            JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512, JWSAlgorithm.ES256,
            JWSAlgorithm.ES384, JWSAlgorithm.ES512);
    /** JAdES header parameters that may be marked critical: they describe the signature, not the payload. */
    private static final Set<String> DEFERRED_CRIT = Set.of("sigT", "x5t#o", "sigX5ts", "srCms", "srAts", "sigPl",
            "adoTst", "sigPId", "cty");
    private static final int MAX_CERTS = 16;
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(SecureXml.MAX_DEPTH)
                    .maxStringLength(1024 * 1024).build()).build());

    private LoteJsonList() {
    }

    /** A list and the pinned signer that verified it. */
    record Verified(Etsi119612List list, X509Certificate signer) {
    }

    /** Verifies the JWS with one of {@code signers} and reads the list. */
    static Verified read(final byte[] bytes, final List<X509Certificate> signers) throws TrustedListException {
        final JWSObject jws;
        try {
            jws = JWSObject.parse(new String(bytes, StandardCharsets.US_ASCII).trim());
        } catch (final java.text.ParseException | RuntimeException e) {
            throw signature("the list is not a JWS compact serialization");
        }
        final JWSHeader header = jws.getHeader();
        if (!ALLOWED.contains(header.getAlgorithm())) {
            throw signature("the signature algorithm is not allowed");
        }
        if (!header.isBase64URLEncodePayload() || header.getCustomParam("sigD") != null) {
            throw signature("a detached or unencoded payload is not accepted");
        }
        X509Certificate verifiedBy = null;
        for (final X509Certificate signer : signers) {
            final JWSVerifier verifier = verifier(signer.getPublicKey());
            try {
                if (verifier != null && jws.verify(verifier)) {
                    verifiedBy = signer;
                    break;
                }
            } catch (final Exception e) {
                // a key of another type, an unknown critical parameter: not this signer
            }
        }
        if (verifiedBy == null) {
            throw signature("the signature does not verify with a configured signer certificate");
        }
        return new Verified(parse(jws.getPayload().toBytes()), verifiedBy);
    }

    private static JWSVerifier verifier(final PublicKey key) {
        try {
            if (key instanceof RSAPublicKey rsa) {
                return new RSASSAVerifier(rsa, DEFERRED_CRIT);
            }
            if (key instanceof ECPublicKey ec) {
                return new ECDSAVerifier(ec, DEFERRED_CRIT);
            }
        } catch (final Exception e) {
            return null;
        }
        return null;
    }

    private static Etsi119612List parse(final byte[] payload) throws TrustedListException {
        final JsonNode root;
        try {
            root = JSON.readTree(payload);
        } catch (final Exception e) {
            throw malformed("the list payload is not valid JSON");
        }
        final JsonNode lote = root == null ? null : root.get("LoTE");
        if (lote == null || !lote.isObject()) {
            throw malformed("the payload is not an ETSI TS 119 602 list (no LoTE object)");
        }
        final JsonNode info = lote.path("ListAndSchemeInformation");
        final JsonNode seq = info.get("LoTESequenceNumber");
        if (seq == null || !seq.canConvertToLong()) {
            throw malformed("the list has no valid LoTESequenceNumber");
        }
        final java.time.Instant issued = Etsi119612List.time(info.path("ListIssueDateTime").asText(null));
        if (issued == null) {
            throw malformed("the list has no valid ListIssueDateTime");
        }
        final java.time.Instant nextUpdate = Etsi119612List.time(info.path("NextUpdate").asText(null));
        final String territory = info.path("SchemeTerritory").asText(null);
        final List<Etsi119612List.Service> services = new ArrayList<>();
        for (final JsonNode entity : lote.path("TrustedEntitiesList")) {
            final JsonNode teInfo = entity.path("TrustedEntityInformation");
            final String provider = multilingual(teInfo.path("TEName"));
            final String country = firstText(teInfo.path("TEAddress").path("TEPostalAddress"), "Country");
            for (final JsonNode svc : entity.path("TrustedEntityServices")) {
                final JsonNode si = svc.path("ServiceInformation");
                final String status = si.path("ServiceStatus").asText(null);
                if (status != null && !current(status)) {
                    continue;
                }
                final List<X509Certificate> certs = new ArrayList<>();
                for (final JsonNode c : si.path("ServiceDigitalIdentity").path("X509Certificates")) {
                    if (certs.size() >= MAX_CERTS) {
                        throw malformed("too many certificates in one service");
                    }
                    certs.add(Etsi119612List.certificate(c.path("val").asText(null)));
                }
                services.add(new Etsi119612List.Service(provider, multilingual(si.path("ServiceName")),
                        si.path("ServiceTypeIdentifier").asText(null), status, null, country, certs));
            }
        }
        return new Etsi119612List(info.path("LoTEType").asText(null), territory, seq.asLong(), issued, nextUpdate,
                List.of(), services);
    }

    private static boolean current(final String status) {
        final String s = status.toLowerCase(Locale.ROOT);
        return !s.endsWith("/withdrawn") && !s.contains("deprecated");
    }

    private static String multilingual(final JsonNode values) {
        String first = null;
        for (final JsonNode v : values) {
            final String text = v.path("value").asText(null);
            if ("en".equalsIgnoreCase(v.path("lang").asText(""))) {
                return text;
            }
            if (first == null) {
                first = text;
            }
        }
        return first;
    }

    private static String firstText(final JsonNode array, final String field) {
        for (final JsonNode v : array) {
            final String text = v.path(field).asText(null);
            if (text != null && !text.isBlank()) {
                return text;
            }
        }
        return null;
    }

    private static TrustedListException signature(final String message) {
        return new TrustedListException(TrustedListException.Kind.SIGNATURE, message);
    }

    private static TrustedListException malformed(final String message) {
        return new TrustedListException(TrustedListException.Kind.MALFORMED, message);
    }
}
