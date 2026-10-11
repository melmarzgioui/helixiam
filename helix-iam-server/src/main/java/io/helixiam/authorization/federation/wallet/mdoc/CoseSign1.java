/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A COSE_Sign1 message (RFC 9052 §4.2) {@code [protected: bstr, unprotected: map, payload: bstr / nil, signature:
 * bstr]}, decoded from the {@link StrictCbor} tree. This is the one COSE_Sign1 verifier of the wallet: mdoc IssuerAuth
 * and DeviceSignature, and the Status List Token in CWT form.
 *
 * <p>Decoding refuses (as {@code INVALID_RESPONSE}): COSE_Mac0 (tag 17) and any other tag than 18, a wrong shape, a
 * protected header that is not an encoded map (a zero-length bstr is the empty map, RFC 9052 §3), a label that appears
 * in both header buckets (RFC 9052 §3), and the {@code crit} parameter (label 2): no extension is understood.
 *
 * <p>Verification takes {@code alg} (label 1) from the <em>protected</em> header only. Only ES256 (-7), ES384 (-35) and
 * ES512 (-36) are allowed by default, each only with a key on its own curve (P-256, P-384, P-521); anything else is
 * {@code ALGORITHM_NOT_ALLOWED}. The signature is raw {@code r||s} and must be exactly twice the coordinate size; any
 * other length, or a signature that does not verify, is {@code false}, never an exception.
 *
 * <p>{@code unprotectedHeader} keys are {@link Long} (integer labels) or {@link String}; values are {@link CborValue}.
 */
public final class CoseSign1 {

    /** ECDSA w/ SHA-256 on P-256. */
    public static final int ES256 = -7;
    /** ECDSA w/ SHA-384 on P-384. */
    public static final int ES384 = -35;
    /** ECDSA w/ SHA-512 on P-521. */
    public static final int ES512 = -36;
    /** ESP256, the fully-specified ES256 (P-256 only). Not allowed by default; the Status List Token admits it. */
    public static final int ESP256 = -9;

    /** The default allow-list (wallet constraint: COSE ES256/384/512). */
    public static final Set<Integer> ALLOWED_ALGORITHMS = Set.of(ES256, ES384, ES512);

    private static final long TAG_COSE_SIGN1 = 18;
    private static final long LABEL_ALG = 1;
    private static final long LABEL_CRIT = 2;
    private static final long LABEL_X5CHAIN = 33;
    private static final byte[] SIGNATURE1 = "Signature1".getBytes(StandardCharsets.US_ASCII);

    private final byte[] protectedHeader;
    private final Map<Object, Object> unprotectedHeader;
    private final byte[] payload;
    private final byte[] signature;
    /** {@link #protectedHeader} decoded once, with {@link CborLimits#DEFAULTS}; the bytes stay the signed input. */
    private final CborValue.Dict protectedParameters;

    /**
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when {@code protectedHeader} is not an encoded map
     *                                     (or empty)
     */
    public CoseSign1(final byte[] protectedHeader, final Map<Object, Object> unprotectedHeader, final byte[] payload,
            final byte[] signature) {
        Objects.requireNonNull(protectedHeader, "protectedHeader");
        Objects.requireNonNull(unprotectedHeader, "unprotectedHeader");
        Objects.requireNonNull(signature, "signature");
        this.protectedHeader = protectedHeader.clone();
        this.unprotectedHeader = Collections.unmodifiableMap(new LinkedHashMap<>(unprotectedHeader));
        this.payload = payload == null ? null : payload.clone();
        this.signature = signature.clone();
        this.protectedParameters = decodeProtected(this.protectedHeader);
    }

    /** The protected header exactly as received (the Sig_structure input). */
    public byte[] protectedHeader() {
        return protectedHeader.clone();
    }

    /** Unprotected header: keys are {@link Long} or {@link String}, values {@link CborValue}. */
    public Map<Object, Object> unprotectedHeader() {
        return unprotectedHeader;
    }

    /** The attached payload, or {@code null} when it is detached. */
    public byte[] payload() {
        return payload == null ? null : payload.clone();
    }

    public byte[] signature() {
        return signature.clone();
    }

    /**
     * A COSE_Sign1 from a {@link StrictCbor} item: COSE_Sign1_Tagged (18) or the untagged array.
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} for anything else
     */
    public static CoseSign1 decode(final CborValue value) {
        CborValue content = value;
        if (content instanceof CborValue.Tagged tagged) {
            if (tagged.tag() != TAG_COSE_SIGN1) {
                throw invalid("COSE message is not a COSE_Sign1");
            }
            content = tagged.content();
        }
        if (!(content instanceof CborValue.Array array) || array.items().size() != 4
                || !(array.items().get(0) instanceof CborValue.Bytes protectedBytes)
                || !(array.items().get(1) instanceof CborValue.Dict unprotected)
                || !(array.items().get(2) instanceof CborValue.Bytes || array.items().get(2) == CborValue.Null.INSTANCE)
                || !(array.items().get(3) instanceof CborValue.Bytes signatureBytes)) {
            throw invalid("COSE message is not a COSE_Sign1");
        }
        final byte[] payloadBytes = array.items().get(2) instanceof CborValue.Bytes b ? b.value() : null;
        final Map<Object, Object> unprotectedHeader = new LinkedHashMap<>();
        for (final Map.Entry<CborValue, CborValue> e : unprotected.entries().entrySet()) {
            unprotectedHeader.put(e.getKey() instanceof CborValue.Int i ? (Object) i.value()
                    : ((CborValue.Text) e.getKey()).value(), e.getValue());
        }
        final CoseSign1 cose = new CoseSign1(protectedBytes.value(), unprotectedHeader, payloadBytes,
                signatureBytes.value());
        final CborValue.Dict protectedHeader = cose.protectedParameters;
        for (final CborValue label : protectedHeader.entries().keySet()) {
            if (unprotected.entries().containsKey(label)) {
                throw invalid("COSE header label appears in both header buckets");
            }
        }
        if (protectedHeader.get(LABEL_CRIT).isPresent() || unprotected.get(LABEL_CRIT).isPresent()) {
            throw invalid("COSE crit header is not supported");
        }
        return cose;
    }

    /** The decoded protected header; a zero-length protected bstr is the empty map. */
    public CborValue.Dict protectedParameters() {
        return protectedParameters;
    }

    private static CborValue.Dict decodeProtected(final byte[] bytes) {
        if (bytes.length == 0) {
            return new CborValue.Dict(Map.of());
        }
        if (!(StrictCbor.decode(bytes, CborLimits.DEFAULTS) instanceof CborValue.Dict dict)) {
            throw invalid("COSE protected header is not a map");
        }
        return dict;
    }

    /**
     * The {@code alg} (label 1) of the protected header.
     *
     * @throws WalletVerificationException {@code ALGORITHM_NOT_ALLOWED} when it is missing there or not an integer
     */
    public int algorithm() {
        if (protectedParameters().get(LABEL_ALG).orElse(null) instanceof CborValue.Int alg
                && alg.value() >= Integer.MIN_VALUE && alg.value() <= Integer.MAX_VALUE) {
            return (int) alg.value();
        }
        throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                "COSE alg is missing from the protected header or not an integer");
    }

    /**
     * The x5chain (label 33, RFC 9360) from the protected or the unprotected header, leaf first. ISO 18013-5 puts the
     * IssuerAuth chain in the unprotected header; that is safe because the chain is validated against trust anchors and
     * the signature must verify with its leaf.
     *
     * @throws WalletVerificationException {@code ISSUER_UNTRUSTED} when it is absent or cannot be parsed
     */
    public List<X509Certificate> x5chain() {
        final CborValue value = protectedParameters().get(LABEL_X5CHAIN)
                .orElse(unprotectedHeader.get(LABEL_X5CHAIN) instanceof CborValue v ? v : null);
        return certificates(value);
    }

    /** As {@link #x5chain()}, from the protected header only (the Status List Token CWT requires it there). */
    public List<X509Certificate> protectedX5chain() {
        return certificates(protectedParameters().get(LABEL_X5CHAIN).orElse(null));
    }

    /** Verifies with the default {@link #ALLOWED_ALGORITHMS}. */
    public boolean verify(final PublicKey key, final byte[] detachedPayloadOrNull) {
        return verify(key, detachedPayloadOrNull, ALLOWED_ALGORITHMS);
    }

    /**
     * Verifies over Sig_structure {@code ["Signature1", protected, external_aad(h''), payload]} (RFC 9052 §4.4). The
     * payload is the attached one, or {@code detachedPayloadOrNull} when the message carries {@code nil}; exactly one
     * must be present ({@code INVALID_RESPONSE} otherwise).
     *
     * @param allowedAlgorithms COSE alg ids accepted here; only ES256, ES384, ES512 and ESP256 are understood
     * @return whether the signature is valid
     * @throws WalletVerificationException {@code ALGORITHM_NOT_ALLOWED} when the protected {@code alg} is not allowed
     *                                     or does not fit {@code key} (an EC key on the alg's curve)
     */
    public boolean verify(final PublicKey key, final byte[] detachedPayloadOrNull,
            final Set<Integer> allowedAlgorithms) {
        final int algId = algorithm();
        final Alg alg = Alg.of(algId);
        if (alg == null || !allowedAlgorithms.contains(algId)) {
            throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "COSE alg is not allowed");
        }
        if ((payload == null) == (detachedPayloadOrNull == null)) {
            throw invalid(payload == null ? "COSE_Sign1 payload is detached but none was given"
                    : "COSE_Sign1 has an attached payload and a detached one was given");
        }
        if (!(key instanceof ECPublicKey ec) || !alg.fits(ec)) {
            throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                    "COSE alg does not fit the key");
        }
        if (signature.length != 2 * ((alg.fieldSize + 7) / 8)) {
            return false;
        }
        final byte[] content = payload != null ? payload : detachedPayloadOrNull;
        try {
            final Signature verifier = Signature.getInstance(alg.jca);
            verifier.initVerify(ec);
            verifier.update(sigStructure(protectedHeader, content));
            return verifier.verify(ECDSA.transcodeSignatureToDER(signature));
        } catch (final GeneralSecurityException | JOSEException e) {
            return false;
        }
    }

    /** {@code ["Signature1", protected, h'', payload]}, definite lengths. */
    private static byte[] sigStructure(final byte[] protectedBytes, final byte[] payload) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(protectedBytes.length + payload.length + 32);
        out.write(0x84); // array(4)
        writeHead(out, 3, SIGNATURE1.length);
        out.writeBytes(SIGNATURE1);
        writeHead(out, 2, protectedBytes.length);
        out.writeBytes(protectedBytes);
        writeHead(out, 2, 0); // external_aad = h''
        writeHead(out, 2, payload.length);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    /** A definite-length CBOR head ({@code major} type, {@code length}). */
    private static void writeHead(final ByteArrayOutputStream out, final int major, final long length) {
        final int m = major << 5;
        if (length < 24) {
            out.write(m | (int) length);
        } else if (length < 0x100) {
            out.write(m | 24);
            out.write((int) length);
        } else if (length < 0x10000) {
            out.write(m | 25);
            out.write((int) (length >> 8));
            out.write((int) length & 0xff);
        } else {
            out.write(m | 26);
            for (int shift = 24; shift >= 0; shift -= 8) {
                out.write((int) (length >> shift) & 0xff);
            }
        }
    }

    private static List<X509Certificate> certificates(final CborValue value) {
        final List<byte[]> der = new ArrayList<>();
        if (value instanceof CborValue.Bytes single) {
            der.add(single.value());
        } else if (value instanceof CborValue.Array array && !array.items().isEmpty()) {
            for (final CborValue item : array.items()) {
                if (!(item instanceof CborValue.Bytes b)) {
                    throw untrusted("x5chain entry is not a byte string");
                }
                der.add(b.value());
            }
        } else {
            throw untrusted(value == null ? "COSE message has no x5chain" : "COSE x5chain is malformed");
        }
        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final List<X509Certificate> chain = new ArrayList<>(der.size());
            for (final byte[] d : der) {
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(d)));
            }
            return List.copyOf(chain);
        } catch (final CertificateException | ClassCastException e) {
            throw untrusted("x5chain certificate cannot be parsed");
        }
    }

    /** The understood ECDSA algorithms: JCA name, curve and coordinate size. */
    private enum Alg {
        ES256("SHA256withECDSA", "secp256r1", 256), ES384("SHA384withECDSA", "secp384r1", 384),
        ES512("SHA512withECDSA", "secp521r1", 521);

        private final String jca;
        private final ECParameterSpec curve;
        private final int fieldSize;

        Alg(final String jca, final String curveName, final int fieldSize) {
            this.jca = jca;
            this.fieldSize = fieldSize;
            try {
                final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(curveName));
                this.curve = parameters.getParameterSpec(ECParameterSpec.class);
            } catch (final GeneralSecurityException e) {
                throw new IllegalStateException("EC curve " + curveName + " is not available", e);
            }
        }

        /** True when {@code key} is on exactly this alg's curve (not merely one of the same size). */
        boolean fits(final ECPublicKey key) {
            final ECParameterSpec params = key.getParams();
            return params.getCurve().equals(curve.getCurve()) && params.getGenerator().equals(curve.getGenerator())
                    && params.getOrder().equals(curve.getOrder());
        }

        static Alg of(final int id) {
            return switch (id) {
                case CoseSign1.ES256, CoseSign1.ESP256 -> ES256;
                case CoseSign1.ES384 -> ES384;
                case CoseSign1.ES512 -> ES512;
                default -> null;
            };
        }
    }

    private static WalletVerificationException invalid(final String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, safeDetail);
    }

    private static WalletVerificationException untrusted(final String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.ISSUER_UNTRUSTED, safeDetail);
    }

    @Override
    public boolean equals(final Object o) {
        return o instanceof CoseSign1 other && Arrays.equals(protectedHeader, other.protectedHeader)
                && unprotectedHeader.equals(other.unprotectedHeader) && Arrays.equals(payload, other.payload)
                && Arrays.equals(signature, other.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(protectedHeader), unprotectedHeader, Arrays.hashCode(payload),
                Arrays.hashCode(signature));
    }

    /** Sizes only: never the payload, which can carry personal data. */
    @Override
    public String toString() {
        return "CoseSign1[protected=" + protectedHeader.length + " bytes, unprotected labels="
                + unprotectedHeader.keySet() + ", payload=" + (payload == null ? "detached" : payload.length + " bytes")
                + ", signature=" + signature.length + " bytes]";
    }
}
