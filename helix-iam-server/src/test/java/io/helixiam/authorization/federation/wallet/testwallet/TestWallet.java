/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.testwallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.Leaf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A test-only issuer and holder wallet: issues SD-JWT VC PIDs (every top-level claim selectively disclosable, flat)
 * signed by a {@link TestPki} leaf with an {@code x5c} header, and presents them with a Key Binding JWT. Digests are
 * computed here independently of production code. Immutable; {@code with*} returns a changed copy, so a negative test
 * changes exactly one thing.
 *
 * <pre>{@code
 * TestWallet wallet = TestWallet.create();
 * TestWallet.SdJwtCredential pid = wallet.sdJwtPid(Map.of("given_name", "Erika"), iat, exp, Optional.empty());
 * String vpToken = wallet.present(pid, Set.of("given_name"), "x509_san_dns:verifier.example", nonce);
 * }</pre>
 */
public final class TestWallet {

    public static final String PID_VCT = "urn:eudi:pid:1";
    public static final String ISSUER = "https://pid-issuer.example";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final CBORFactory CBOR = new CBORFactory();

    private final TestPki pki;
    private final Leaf issuer;
    private final JWSAlgorithm alg;
    private final String typ;
    private final String vct;
    private final String sdAlg;
    private final JWK holderKey;
    private final boolean includeCnf;
    private final boolean includeX5c;
    private final Map<String, Object> extraPayload;

    private TestWallet(final TestPki pki, final Leaf issuer, final JWSAlgorithm alg, final String typ,
            final String vct, final String sdAlg, final JWK holderKey, final boolean includeCnf,
            final boolean includeX5c, final Map<String, Object> extraPayload) {
        this.pki = pki;
        this.issuer = issuer;
        this.alg = alg;
        this.typ = typ;
        this.vct = vct;
        this.sdAlg = sdAlg;
        this.holderKey = holderKey;
        this.includeCnf = includeCnf;
        this.includeX5c = includeX5c;
        this.extraPayload = Collections.unmodifiableMap(new LinkedHashMap<>(extraPayload));
    }

    /** A new PKI, an EC P-256 issuer leaf (ES256), typ {@code dc+sd-jwt}, {@code sha-256}, an EC P-256 holder key. */
    public static TestWallet create() {
        final TestPki pki = TestPki.create();
        return new TestWallet(pki, pki.issueLeaf(TestPki.LeafSpec.defaults()), JWSAlgorithm.ES256, "dc+sd-jwt",
                PID_VCT, "sha-256", ecKey(Curve.P_256), true, true, Map.of("iss", ISSUER));
    }

    /** A fresh EC holder key on {@code curve}. */
    public static ECKey ecKey(final Curve curve) {
        try {
            return new ECKeyGenerator(curve).generate();
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public TestPki pki() {
        return pki;
    }

    public Leaf issuer() {
        return issuer;
    }

    public JWK holderKey() {
        return holderKey;
    }

    /** Issuer leaf and the JWS {@code alg} it signs with (no consistency check: tests use mismatches). */
    public TestWallet withIssuer(final Leaf leaf, final JWSAlgorithm signingAlg) {
        return new TestWallet(pki, leaf, signingAlg, typ, vct, sdAlg, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withTyp(final String value) {
        return new TestWallet(pki, issuer, alg, value, vct, sdAlg, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withVct(final String value) {
        return new TestWallet(pki, issuer, alg, typ, value, sdAlg, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withSdAlg(final String value) {
        return new TestWallet(pki, issuer, alg, typ, vct, value, holderKey, includeCnf, includeX5c, extraPayload);
    }

    public TestWallet withHolderKey(final JWK value) {
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, value, includeCnf, includeX5c, extraPayload);
    }

    /** Leave {@code cnf} out of the issuer payload (a credential that cannot be holder-bound). */
    public TestWallet withoutCnf() {
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, holderKey, false, includeX5c, extraPayload);
    }

    public TestWallet withoutX5c() {
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, holderKey, includeCnf, false, extraPayload);
    }

    /** Sets (or, with {@code null}, removes) a plain, always-disclosed issuer payload member such as iss or nbf. */
    public TestWallet withPayloadClaim(final String name, final Object value) {
        final Map<String, Object> extra = new LinkedHashMap<>(extraPayload);
        if (value == null) {
            extra.remove(name);
        } else {
            extra.put(name, value);
        }
        return new TestWallet(pki, issuer, alg, typ, vct, sdAlg, holderKey, includeCnf, includeX5c, extra);
    }

    /** An issued SD-JWT VC: the Issuer-signed JWT, one disclosure per claim name, and the holder's private key. */
    public record SdJwtCredential(String issuerJwt, Map<String, String> disclosures, JWK holderKey) {

        /** Same disclosures and holder, a different Issuer-signed JWT (tampering tests). */
        public SdJwtCredential withIssuerJwt(final String value) {
            return new SdJwtCredential(value, disclosures, holderKey);
        }
    }

    /**
     * A PID: {@code claims} are each selectively disclosable (one flat disclosure per top-level member, plus a decoy);
     * {@code vct}, {@code iat}, {@code exp}, {@code status}, {@code cnf}, {@code _sd_alg} and the extra payload claims
     * are plain. {@code iat} / {@code exp} may be {@code null} (omitted).
     */
    public SdJwtCredential sdJwtPid(final Map<String, Object> claims, final Instant iat, final Instant exp,
            final Optional<StatusReference> status) {
        final Map<String, String> disclosures = new LinkedHashMap<>();
        final List<String> digests = new ArrayList<>();
        for (final Map.Entry<String, Object> claim : claims.entrySet()) {
            final String disclosure = disclosure(claim.getKey(), claim.getValue());
            disclosures.put(claim.getKey(), disclosure);
            digests.add(digest(disclosure, sdAlg));
        }
        digests.add(digest(disclosure("decoy", "decoy"), sdAlg)); // never presented
        Collections.sort(digests);

        final Map<String, Object> payload = new LinkedHashMap<>(extraPayload);
        if (vct != null) {
            payload.put("vct", vct);
        }
        if (iat != null) {
            payload.put("iat", iat.getEpochSecond());
        }
        if (exp != null) {
            payload.put("exp", exp.getEpochSecond());
        }
        payload.put("_sd_alg", sdAlg);
        payload.put("_sd", digests);
        if (includeCnf) {
            payload.put("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
        }
        status.ifPresent(s -> payload.put("status",
                Map.of("status_list", Map.of("idx", s.idx(), "uri", s.uri()))));
        return new SdJwtCredential(signIssuerJwt(json(payload)), disclosures, holderKey);
    }

    /** Signs {@code rawPayloadJson} byte-exact (so a test can repeat a key) with this wallet's issuer header. */
    public String signIssuerJwt(final String rawPayloadJson) {
        final JWSHeader.Builder header = new JWSHeader.Builder(alg);
        if (typ != null) {
            header.type(new JOSEObjectType(typ));
        }
        if (includeX5c) {
            final List<Base64> x5c = new ArrayList<>();
            for (final X509Certificate cert : issuer.chain()) {
                try {
                    x5c.add(Base64.encode(cert.getEncoded()));
                } catch (final Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            header.x509CertChain(x5c);
        }
        return sign(header.build(), rawPayloadJson, signer(issuer.privateKey()));
    }

    // ------------------------------------------------------------------------------------------- presentation

    /** The holder's KB-JWT parameters; {@link #of} gives a valid one, {@code with*} breaks exactly one thing. */
    public record KeyBinding(String typ, Object aud, String nonce, Instant iat, JWK signingKey, JWSAlgorithm alg,
            String sdHash, String sdHashAlg, String rawPayloadJson) {

        /** typ {@code kb+jwt}, iat now, signed with the credential's holder key, correct sd_hash. */
        public static KeyBinding of(final String aud, final String nonce) {
            return new KeyBinding("kb+jwt", aud, nonce, Instant.now(), null, null, null, null, null);
        }

        public KeyBinding withTyp(final String value) {
            return new KeyBinding(value, aud, nonce, iat, signingKey, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        /** A string or a JSON array (list). */
        public KeyBinding withAud(final Object value) {
            return new KeyBinding(typ, value, nonce, iat, signingKey, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        public KeyBinding withIat(final Instant value) {
            return new KeyBinding(typ, aud, nonce, value, signingKey, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        /** Sign with another key (and its default alg unless {@link #withAlg} is also given). */
        public KeyBinding withSigningKey(final JWK value) {
            return new KeyBinding(typ, aud, nonce, iat, value, alg, sdHash, sdHashAlg, rawPayloadJson);
        }

        public KeyBinding withAlg(final JWSAlgorithm value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, value, sdHash, sdHashAlg, rawPayloadJson);
        }

        /** A fixed sd_hash value instead of the computed one. */
        public KeyBinding withSdHash(final String value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, alg, value, sdHashAlg, rawPayloadJson);
        }

        /** Compute sd_hash with this hash instead of the credential's {@code _sd_alg}. */
        public KeyBinding withSdHashAlg(final String value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, alg, sdHash, value, rawPayloadJson);
        }

        /** Sign this payload JSON byte-exact; {@code %SD_HASH%} is replaced with the computed sd_hash. */
        public KeyBinding withRawPayload(final String value) {
            return new KeyBinding(typ, aud, nonce, iat, signingKey, alg, sdHash, sdHashAlg, value);
        }
    }

    /** {@code <issuer-jwt>~<disclosures of disclose>~<kb-jwt>} with a valid KB-JWT. */
    public String present(final SdJwtCredential credential, final Set<String> disclose, final String aud,
            final String nonce) {
        return present(credential, disclose, KeyBinding.of(aud, nonce));
    }

    public String present(final SdJwtCredential credential, final Set<String> disclose, final KeyBinding kb) {
        final String sdJwt = presentWithoutKeyBinding(credential, disclose);
        final String hash = kb.sdHash() != null ? kb.sdHash()
                : digest(sdJwt, kb.sdHashAlg() != null ? kb.sdHashAlg() : sdAlg);
        final String payload;
        if (kb.rawPayloadJson() != null) {
            payload = kb.rawPayloadJson().replace("%SD_HASH%", hash);
        } else {
            final Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iat", kb.iat().getEpochSecond());
            claims.put("aud", kb.aud());
            claims.put("nonce", kb.nonce());
            claims.put("sd_hash", hash);
            payload = json(claims);
        }
        final JWK key = kb.signingKey() != null ? kb.signingKey() : credential.holderKey();
        final JWSAlgorithm signingAlg = kb.alg() != null ? kb.alg() : defaultAlg(key);
        final JWSHeader.Builder header = new JWSHeader.Builder(signingAlg);
        if (kb.typ() != null) {
            header.type(new JOSEObjectType(kb.typ()));
        }
        return sdJwt + sign(header.build(), payload, signer(key));
    }

    /** {@code <issuer-jwt>~<disclosures>~} (no KB-JWT). Unknown names in {@code disclose} fail the test. */
    public String presentWithoutKeyBinding(final SdJwtCredential credential, final Set<String> disclose) {
        final StringBuilder sb = new StringBuilder(credential.issuerJwt()).append('~');
        for (final String name : disclose) {
            final String d = credential.disclosures().get(name);
            if (d == null) {
                throw new IllegalArgumentException("no disclosure for " + name);
            }
            sb.append(d).append('~');
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------------------------------- mdoc (ISO 18013-5)

    /** The PID docType, also its namespace (ARF PID rulebook). */
    public static final String MDOC_PID_DOCTYPE = "eu.europa.ec.eudi.pid.1";

    /** A CBOR tag for {@link #cbor}: {@code tag} applied to {@code content}. */
    public record CborTag(long tag, Object content) {
    }

    /**
     * An issued mdoc. {@code issuerAuth} is the untagged COSE_Sign1 over {@code mso} as a {@link #cbor} structure;
     * {@code items} maps each elementIdentifier to its IssuerSignedItemBytes ({@code #6.24(bstr)}) structure;
     * {@code deviceKey} is the holder's private EC key. The writer is deterministic, so {@link #cbor} of a structure
     * always gives the bytes that were signed and digested.
     */
    public record MdocCredential(String docType, List<Object> issuerAuth, byte[] mso, Map<String, CborTag> items,
            ECKey deviceKey) {

        /** The encoded COSE_Sign1 (IssuerAuth). */
        public byte[] issuerAuthBytes() {
            return cbor(issuerAuth);
        }

        /** The encoded IssuerSignedItemBytes of {@code elementIdentifier}, exactly as digested in the MSO. */
        public byte[] itemBytes(final String elementIdentifier) {
            return cbor(items.get(elementIdentifier));
        }
    }

    /**
     * A PID mdoc: one IssuerSignedItem per claim in namespace {@link #MDOC_PID_DOCTYPE}, an MSO with SHA-256 digests,
     * the holder's P-256 device key as a COSE_Key, the validity times as tdate and the optional status list
     * reference, signed by this wallet's issuer leaf (alg from its curve, x5chain in the unprotected header as ISO
     * 18013-5 places it).
     */
    public MdocCredential mdocPid(final Map<String, Object> claims, final Instant signed, final Instant validFrom,
            final Instant validUntil, final Optional<StatusReference> status) {
        final ECKey deviceKey = ecKey(Curve.P_256);
        final Map<String, CborTag> items = new LinkedHashMap<>();
        final Map<Object, Object> digests = new LinkedHashMap<>();
        int digestId = 0;
        for (final Map.Entry<String, Object> claim : claims.entrySet()) {
            final byte[] random = new byte[16];
            RANDOM.nextBytes(random);
            final Map<Object, Object> item = new LinkedHashMap<>();
            item.put("digestID", digestId);
            item.put("random", random);
            item.put("elementIdentifier", claim.getKey());
            item.put("elementValue", claim.getValue());
            final CborTag itemBytes = new CborTag(24, cbor(item));
            items.put(claim.getKey(), itemBytes);
            digests.put(digestId++, sha("SHA-256", cbor(itemBytes)));
        }
        final Map<String, Map<Object, Object>> valueDigests = new LinkedHashMap<>();
        valueDigests.put(MDOC_PID_DOCTYPE, digests);
        final Map<Object, Object> mso = mso(MDOC_PID_DOCTYPE, "SHA-256", valueDigests, coseKey(deviceKey), signed,
                validFrom, validUntil);
        status.ifPresent(s -> mso.put("status", Map.of("status_list", Map.of("idx", s.idx(), "uri", s.uri()))));
        final byte[] msoBytes = cbor(new CborTag(24, cbor(mso)));
        final Map<Object, Object> unprotectedHeader = new LinkedHashMap<>();
        unprotectedHeader.put(33, x5chain(issuer.chain()));
        final List<Object> issuerAuth = coseSign1(Map.of(1, coseAlg(issuer.privateKey())), unprotectedHeader,
                msoBytes, false, issuer.privateKey());
        return new MdocCredential(MDOC_PID_DOCTYPE, issuerAuth, msoBytes, Collections.unmodifiableMap(items),
                deviceKey);
    }

    /**
     * A mutable MobileSecurityObject map, members in the ISO presentation order, so a test can change one member and
     * re-encode it with {@link #cbor}. Times are tdate (tag 0).
     */
    public static Map<Object, Object> mso(final String docType, final String digestAlgorithm,
            final Map<String, Map<Object, Object>> valueDigests, final Map<Object, Object> deviceKey,
            final Instant signed, final Instant validFrom, final Instant validUntil) {
        final Map<Object, Object> validity = new LinkedHashMap<>();
        validity.put("signed", tdate(signed));
        validity.put("validFrom", tdate(validFrom));
        validity.put("validUntil", tdate(validUntil));
        final Map<Object, Object> keyInfo = new LinkedHashMap<>();
        keyInfo.put("deviceKey", deviceKey);
        final Map<Object, Object> mso = new LinkedHashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", digestAlgorithm);
        mso.put("valueDigests", new LinkedHashMap<>(valueDigests));
        mso.put("deviceKeyInfo", keyInfo);
        mso.put("docType", docType);
        mso.put("validityInfo", validity);
        return mso;
    }

    /** {@code #6.0(tstr)}: an RFC 3339 date-time in UTC without fractions. */
    public static CborTag tdate(final Instant instant) {
        return new CborTag(0, instant.truncatedTo(ChronoUnit.SECONDS).toString());
    }

    /** A mutable COSE_Key (RFC 9052 §7, EC2) of {@code key}'s public part: {1: 2, -1: crv, -2: x, -3: y}. */
    public static Map<Object, Object> coseKey(final ECKey key) {
        final int crv = Curve.P_384.equals(key.getCurve()) ? 2 : Curve.P_521.equals(key.getCurve()) ? 3 : 1;
        final Map<Object, Object> coseKey = new LinkedHashMap<>();
        coseKey.put(1, 2);
        coseKey.put(-1, crv);
        coseKey.put(-2, key.getX().decode());
        coseKey.put(-3, key.getY().decode());
        return coseKey;
    }

    /** The COSE alg for an EC key: -7 (P-256), -35 (P-384), -36 (P-521). */
    public static int coseAlg(final PrivateKey key) {
        final int bits = ((ECPrivateKey) key).getParams().getCurve().getField().getFieldSize();
        return bits == 384 ? -35 : bits == 521 ? -36 : -7;
    }

    /** x5chain (RFC 9360): one bstr for a single certificate, else an array of DER bstr. */
    public static Object x5chain(final List<X509Certificate> chain) {
        final List<Object> der = new ArrayList<>();
        for (final X509Certificate cert : chain) {
            try {
                der.add(cert.getEncoded());
            } catch (final java.security.cert.CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
        return der.size() == 1 ? der.get(0) : der;
    }

    /**
     * An untagged COSE_Sign1 structure {@code [protected, unprotected, payload | null, signature]} (RFC 9052 §4.2) for
     * {@link #cbor}. The signature is raw {@code r||s} ECDSA over {@code ["Signature1", protected, h'', payload]},
     * hashed per the key's curve and independent of the header {@code alg}, so a test can disagree with it. An empty
     * {@code protectedHeader} is encoded as a zero-length bstr. {@code detached} writes a null payload and signs
     * {@code payload} as the detached content.
     */
    public static List<Object> coseSign1(final Map<Object, Object> protectedHeader,
            final Map<Object, Object> unprotectedHeader, final byte[] payload, final boolean detached,
            final PrivateKey key) {
        final byte[] protectedBytes = protectedHeader.isEmpty() ? new byte[0] : cbor(protectedHeader);
        final byte[] toBeSigned = cbor(List.of("Signature1", protectedBytes, new byte[0], payload));
        final List<Object> cose = new ArrayList<>();
        cose.add(protectedBytes);
        cose.add(unprotectedHeader);
        cose.add(detached ? null : payload);
        cose.add(ecdsaRaw(key, toBeSigned));
        return cose;
    }

    /**
     * A DeviceResponse {@code {version, documents: [Document], status: 0}} disclosing {@code disclose}. DeviceSigned has
     * empty DeviceNameSpaces and a {@code deviceSignature}: a detached ES256 COSE_Sign1 by the device key over
     * DeviceAuthenticationBytes {@code #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, docType,
     * DeviceNameSpacesBytes])}. {@code sessionTranscript} is the encoded SessionTranscript, embedded byte-exact.
     */
    public static byte[] mdocDeviceResponse(final MdocCredential credential, final Set<String> disclose,
            final byte[] sessionTranscript) {
        final List<Object> items = new ArrayList<>();
        for (final String name : disclose) {
            final CborTag item = credential.items().get(name);
            if (item == null) {
                throw new IllegalArgumentException("no IssuerSignedItem for " + name);
            }
            items.add(item);
        }
        final CborTag deviceNameSpaces = new CborTag(24, cbor(Map.of()));
        final ByteArrayOutputStream deviceAuthentication = new ByteArrayOutputStream();
        deviceAuthentication.write(0x84); // array(4); written by hand so the transcript is embedded byte-exact
        deviceAuthentication.writeBytes(cbor("DeviceAuthentication"));
        deviceAuthentication.writeBytes(sessionTranscript);
        deviceAuthentication.writeBytes(cbor(credential.docType()));
        deviceAuthentication.writeBytes(cbor(deviceNameSpaces));
        final byte[] deviceAuthenticationBytes = cbor(new CborTag(24, deviceAuthentication.toByteArray()));
        final PrivateKey deviceKey;
        try {
            deviceKey = credential.deviceKey().toECPrivateKey();
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
        final List<Object> deviceSignature = coseSign1(Map.of(1, -7), Map.of(), deviceAuthenticationBytes, true,
                deviceKey);

        final Map<Object, Object> issuerSigned = new LinkedHashMap<>();
        issuerSigned.put("nameSpaces", Map.of(credential.docType(), items));
        issuerSigned.put("issuerAuth", credential.issuerAuth());
        final Map<Object, Object> deviceSigned = new LinkedHashMap<>();
        deviceSigned.put("nameSpaces", deviceNameSpaces);
        deviceSigned.put("deviceAuth", Map.of("deviceSignature", deviceSignature));
        final Map<Object, Object> document = new LinkedHashMap<>();
        document.put("docType", credential.docType());
        document.put("issuerSigned", issuerSigned);
        document.put("deviceSigned", deviceSigned);
        final Map<Object, Object> response = new LinkedHashMap<>();
        response.put("version", "1.0");
        response.put("documents", List.of(document));
        response.put("status", 0);
        return cbor(response);
    }

    /**
     * Encodes {@code value} with Jackson's {@link CBORGenerator} (the CBOR writer the wallet tests use), definite
     * lengths: Map (Integer/Long or String keys), List, String, Integer/Long, byte[], Boolean, null and
     * {@link CborTag}. Deterministic for a given structure.
     */
    public static byte[] cbor(final Object value) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (CBORGenerator g = CBOR.createGenerator(out)) {
            writeCbor(g, value);
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
        return out.toByteArray();
    }

    private static void writeCbor(final CBORGenerator g, final Object value) throws IOException {
        if (value == null) {
            g.writeNull();
        } else if (value instanceof String s) {
            g.writeString(s);
        } else if (value instanceof Integer || value instanceof Long) {
            g.writeNumber(((Number) value).longValue());
        } else if (value instanceof Boolean b) {
            g.writeBoolean(b);
        } else if (value instanceof byte[] bytes) {
            g.writeBinary(bytes);
        } else if (value instanceof CborTag tag) {
            g.writeTag((int) tag.tag());
            writeCbor(g, tag.content());
        } else if (value instanceof List<?> list) {
            g.writeStartArray(list, list.size());
            for (final Object item : list) {
                writeCbor(g, item);
            }
            g.writeEndArray();
        } else if (value instanceof Map<?, ?> map) {
            g.writeStartObject(map, map.size());
            for (final Map.Entry<?, ?> e : map.entrySet()) {
                if (e.getKey() instanceof String name) {
                    g.writeFieldName(name);
                } else if (e.getKey() instanceof Integer || e.getKey() instanceof Long) {
                    g.writeFieldId(((Number) e.getKey()).longValue());
                } else {
                    throw new IllegalArgumentException("CBOR map key must be text or integer");
                }
                writeCbor(g, e.getValue());
            }
            g.writeEndObject();
        } else {
            throw new IllegalArgumentException("cannot encode " + value.getClass().getSimpleName());
        }
    }

    /** Raw {@code r||s} ECDSA (COSE form) over {@code data}, hash per the key's curve. */
    private static byte[] ecdsaRaw(final PrivateKey key, final byte[] data) {
        final int bits = ((ECPrivateKey) key).getParams().getCurve().getField().getFieldSize();
        final String jca = bits == 384 ? "SHA384withECDSA" : bits == 521 ? "SHA512withECDSA" : "SHA256withECDSA";
        try {
            final Signature ecdsa = Signature.getInstance(jca);
            ecdsa.initSign(key);
            ecdsa.update(data);
            return ECDSA.transcodeSignatureToConcat(ecdsa.sign(), 2 * ((bits + 7) / 8));
        } catch (final GeneralSecurityException | JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code jcaName} digest of {@code data}; independent of production code. */
    public static byte[] sha(final String jcaName, final byte[] data) {
        try {
            return MessageDigest.getInstance(jcaName).digest(data);
        } catch (final java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------------------------------- helpers

    /** base64url(H(ASCII(input))) with an SD-JWT hash name (sha-256/384/512); independent of production code. */
    public static String digest(final String input, final String sdHashName) {
        try {
            final String jca = switch (sdHashName) {
                case "sha-256" -> "SHA-256";
                case "sha-384" -> "SHA-384";
                case "sha-512" -> "SHA-512";
                default -> throw new IllegalArgumentException(sdHashName);
            };
            return b64url(MessageDigest.getInstance(jca).digest(input.getBytes(StandardCharsets.US_ASCII)));
        } catch (final java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String b64url(final byte[] bytes) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String b64url(final String utf8) {
        return b64url(utf8.getBytes(StandardCharsets.UTF_8));
    }

    public static String json(final Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A fresh object-property disclosure {@code [salt, name, value]}, base64url-encoded. */
    public static String disclosure(final String name, final Object value) {
        final byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return b64url(json(List.of(b64url(salt), name, value)));
    }

    private static String sign(final JWSHeader header, final String payloadJson, final JWSSigner signer) {
        try {
            final JWSObject jws = new JWSObject(header, new Payload(payloadJson.getBytes(StandardCharsets.UTF_8)));
            jws.sign(signer);
            return jws.serialize();
        } catch (final JOSEException e) {
            throw new IllegalStateException("Could not sign the test JWT", e);
        }
    }

    private static JWSSigner signer(final PrivateKey key) {
        try {
            return key instanceof ECPrivateKey ec ? new ECDSASigner(ec) : new RSASSASigner(key);
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JWSSigner signer(final JWK key) {
        try {
            return key instanceof ECKey ec ? new ECDSASigner(ec) : new RSASSASigner(key.toRSAKey());
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JWSAlgorithm defaultAlg(final JWK key) {
        if (key instanceof ECKey ec) {
            final Curve curve = ec.getCurve();
            return Curve.P_384.equals(curve) ? JWSAlgorithm.ES384
                    : Curve.P_521.equals(curve) ? JWSAlgorithm.ES512 : JWSAlgorithm.ES256;
        }
        return JWSAlgorithm.PS256;
    }
}
