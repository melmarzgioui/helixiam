/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.status.StatusReference;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The ISO 18013-5 MobileSecurityObject (draft 2nd edition §12.3.4, see {@code docs/eudi-wallet-spec-notes.md} §6.2):
 * the issuer-signed IssuerAuth payload that carries the digests of every IssuerSignedItem, the holder's device key,
 * the validity window and the optional status-list reference. Decoding is structural only: signature, chain, times
 * against {@code now}, docType and digests are checked by the presentation verifier.
 *
 * <p>Refused by {@link #decode}: a digest algorithm other than {@code SHA-256}, {@code SHA-384}, {@code SHA-512}
 * (upper case, draft Table 16) as {@code ALGORITHM_NOT_ALLOWED}; everything else as {@code INVALID_RESPONSE}: a payload
 * that is not tag 24 wrapping a map, missing or mistyped members, a digest ID outside {@code 0..2^31-1}, a digest whose
 * length does not match the algorithm, a device key that is not an EC2 COSE_Key on P-256/384/521 with both
 * coordinates of the curve's size and the point on the curve (or that carries a private key), a validity time that is
 * not tdate (tag 0 on an RFC 3339 date-time), {@code validFrom < signed} or {@code validUntil <= validFrom}, and a
 * malformed {@code status}.
 *
 * <p>{@code status} is null only when the MSO has no {@code status} member. A present {@code status} is a
 * {@link StatusList} when it holds a {@code status_list} {@code {idx, uri, ? certificate}} (draft §12.3.6), otherwise a
 * {@link NotEvaluable} (e.g. only an {@code identifier_list}): present but not evaluable here, never read as "no
 * status", so revocation can never be skipped silently. A structurally malformed {@code status}, {@code status_list} or
 * {@code identifier_list} is {@code INVALID_RESPONSE}.
 *
 * @param valueDigests namespace → digest ID → digest; unmodifiable, digests copied on read
 * @param deviceKey    the holder's EC public key ({@code deviceKeyInfo.deviceKey})
 */
public record MobileSecurityObject(String version, String digestAlgorithm, String docType,
        Map<String, Map<Integer, byte[]>> valueDigests, PublicKey deviceKey, Instant signed, Instant validFrom,
        Instant validUntil, Status status) {

    /** A present MSO {@code status} (draft §12.3.6). */
    public sealed interface Status permits StatusList, NotEvaluable {
    }

    /**
     * {@code status.status_list}: a Token Status List reference to evaluate.
     *
     * @param certificate the optional ISO trust point for the list signer (draft §12.3.6.2), DER, or null. Kept for the
     *                    status-list wiring; trust is not decided here
     */
    public record StatusList(StatusReference reference, byte[] certificate) implements Status {
        public StatusList {
            Objects.requireNonNull(reference, "reference");
            certificate = certificate == null ? null : certificate.clone();
        }

        @Override
        public byte[] certificate() {
            return certificate == null ? null : certificate.clone();
        }

        @Override
        public boolean equals(final Object o) {
            return o instanceof StatusList other && reference.equals(other.reference)
                    && java.util.Arrays.equals(certificate, other.certificate);
        }

        @Override
        public int hashCode() {
            return 31 * reference.hashCode() + java.util.Arrays.hashCode(certificate);
        }

        @Override
        public String toString() {
            return "StatusList[" + reference + ", certificate=" + (certificate == null ? "none"
                    : certificate.length + " bytes") + "]";
        }
    }

    /**
     * A present {@code status} without a {@code status_list} (only an {@code identifier_list}, nothing, or unknown
     * members): it exists, so it is never "no status", but it cannot be evaluated here. The verifier applies the
     * unavailability policy to it.
     *
     * @param mechanisms the member names it carries, e.g. {@code [identifier_list]}
     */
    public record NotEvaluable(List<String> mechanisms) implements Status {
        public NotEvaluable {
            mechanisms = List.copyOf(mechanisms);
        }
    }

    private static final Map<String, Integer> DIGEST_LENGTHS = Map.of("SHA-256", 32, "SHA-384", 48, "SHA-512", 64);
    private static final long TAG_TDATE = 0;

    private static final long COSE_KEY_KTY = 1;
    private static final long COSE_KEY_CRV = -1;
    private static final long COSE_KEY_X = -2;
    private static final long COSE_KEY_Y = -3;
    private static final long COSE_KEY_D = -4;
    private static final long KTY_EC2 = 2;

    public MobileSecurityObject {
        Objects.requireNonNull(valueDigests, "valueDigests");
        final Map<String, Map<Integer, byte[]>> copy = new LinkedHashMap<>();
        valueDigests.forEach((ns, digests) -> {
            final Map<Integer, byte[]> inner = new LinkedHashMap<>();
            digests.forEach((id, digest) -> inner.put(id, digest.clone()));
            copy.put(ns, new DigestMap(inner));
        });
        valueDigests = Collections.unmodifiableMap(copy);
    }

    /**
     * Decodes MobileSecurityObjectBytes: {@code #6.24(bstr .cbor MobileSecurityObject)}, the IssuerAuth payload. Both
     * the outer item and the embedded MSO are decoded by {@link StrictCbor} with {@link CborLimits#DEFAULTS}.
     *
     * @throws WalletVerificationException see the class description
     */
    public static MobileSecurityObject decode(final byte[] taggedPayload) {
        if (!(StrictCbor.decode(taggedPayload) instanceof CborValue.Embedded embedded)) {
            throw invalid("MSO is not tag-24 MobileSecurityObjectBytes");
        }
        if (!(StrictCbor.decode(embedded.content()) instanceof CborValue.Dict mso)) {
            throw invalid("MSO is not a map");
        }
        final String version = text(mso, "version");
        if (!(mso.get("digestAlgorithm").orElse(null) instanceof CborValue.Text algText)) {
            throw invalid("MSO digestAlgorithm is missing or not a text string");
        }
        final String digestAlgorithm = algText.value();
        final Integer digestLength = DIGEST_LENGTHS.get(digestAlgorithm);
        if (digestLength == null) {
            throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                    "MSO digestAlgorithm is not allowed");
        }
        final String docType = text(mso, "docType");
        final Map<String, Map<Integer, byte[]>> valueDigests = valueDigests(mso, digestLength);

        if (!(mso.get("deviceKeyInfo").orElse(null) instanceof CborValue.Dict keyInfo)
                || !(keyInfo.get("deviceKey").orElse(null) instanceof CborValue.Dict coseKey)) {
            throw invalid("MSO deviceKeyInfo.deviceKey is missing");
        }
        final PublicKey deviceKey = ecPublicKey(coseKey);

        if (!(mso.get("validityInfo").orElse(null) instanceof CborValue.Dict validity)) {
            throw invalid("MSO validityInfo is missing");
        }
        final Instant signed = tdate(validity, "signed", true);
        final Instant validFrom = tdate(validity, "validFrom", true);
        final Instant validUntil = tdate(validity, "validUntil", true);
        tdate(validity, "expectedUpdate", false);
        if (validFrom.isBefore(signed) || !validUntil.isAfter(validFrom)) {
            throw invalid("MSO validityInfo is inconsistent");
        }

        return new MobileSecurityObject(version, digestAlgorithm, docType, valueDigests, deviceKey, signed, validFrom,
                validUntil, status(mso.get("status").orElse(null)));
    }

    private static String text(final CborValue.Dict map, final String key) {
        if (map.get(key).orElse(null) instanceof CborValue.Text t && !t.value().isBlank()) {
            return t.value();
        }
        throw invalid("MSO " + key + " is missing or not a text string");
    }

    private static Map<String, Map<Integer, byte[]>> valueDigests(final CborValue.Dict mso, final int digestLength) {
        if (!(mso.get("valueDigests").orElse(null) instanceof CborValue.Dict namespaces)) {
            throw invalid("MSO valueDigests is missing");
        }
        final Map<String, Map<Integer, byte[]>> out = new LinkedHashMap<>();
        for (final Map.Entry<CborValue, CborValue> ns : namespaces.entries().entrySet()) {
            if (!(ns.getKey() instanceof CborValue.Text name) || !(ns.getValue() instanceof CborValue.Dict digests)) {
                throw invalid("MSO valueDigests is malformed");
            }
            final Map<Integer, byte[]> byId = new LinkedHashMap<>();
            for (final Map.Entry<CborValue, CborValue> d : digests.entries().entrySet()) {
                if (!(d.getKey() instanceof CborValue.Int id) || id.value() < 0 || id.value() > Integer.MAX_VALUE
                        || !(d.getValue() instanceof CborValue.Bytes digest)) {
                    throw invalid("MSO valueDigests is malformed");
                }
                final byte[] value = digest.value();
                if (value.length != digestLength) {
                    throw invalid("MSO digest length does not match digestAlgorithm");
                }
                byId.put((int) id.value(), value);
            }
            out.put(name.value(), byId);
        }
        return out;
    }

    /** An EC2 COSE_Key (RFC 9053 §7.1.1) → EC public key, the point checked to be on the curve. */
    private static PublicKey ecPublicKey(final CborValue.Dict key) {
        if (!(key.get(COSE_KEY_KTY).orElse(null) instanceof CborValue.Int kty) || kty.value() != KTY_EC2) {
            throw invalid("deviceKey is not an EC2 COSE_Key");
        }
        if (key.get(COSE_KEY_D).isPresent()) {
            throw invalid("deviceKey carries a private key");
        }
        final String curveName;
        final int size;
        if (!(key.get(COSE_KEY_CRV).orElse(null) instanceof CborValue.Int crv)) {
            throw invalid("deviceKey crv is missing");
        }
        switch ((int) Math.max(-1, Math.min(4, crv.value()))) {
            case 1 -> {
                curveName = "secp256r1";
                size = 32;
            }
            case 2 -> {
                curveName = "secp384r1";
                size = 48;
            }
            case 3 -> {
                curveName = "secp521r1";
                size = 66;
            }
            default -> throw invalid("deviceKey crv is not P-256, P-384 or P-521");
        }
        if (!(key.get(COSE_KEY_X).orElse(null) instanceof CborValue.Bytes x)
                || !(key.get(COSE_KEY_Y).orElse(null) instanceof CborValue.Bytes y)
                || x.value().length != size || y.value().length != size) {
            throw invalid("deviceKey coordinates do not match its crv");
        }
        try {
            final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName));
            final ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
            final ECPoint point = new ECPoint(new BigInteger(1, x.value()), new BigInteger(1, y.value()));
            if (!onCurve(spec.getCurve(), point)) {
                throw invalid("deviceKey point is not on its curve");
            }
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
        } catch (final GeneralSecurityException e) {
            throw invalid("deviceKey cannot be built");
        }
    }

    /** {@code y² = x³ + ax + b (mod p)} with {@code 0 <= x, y < p} (prime-field curves only). */
    private static boolean onCurve(final EllipticCurve curve, final ECPoint point) {
        final BigInteger p = ((java.security.spec.ECFieldFp) curve.getField()).getP();
        final BigInteger x = point.getAffineX();
        final BigInteger y = point.getAffineY();
        if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
            return false;
        }
        final BigInteger left = y.multiply(y).mod(p);
        final BigInteger right = x.pow(3).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        return left.equals(right);
    }

    /** A tdate member ({@code #6.0(tstr)}, RFC 3339); null when absent and not required. */
    private static Instant tdate(final CborValue.Dict validity, final String key, final boolean required) {
        final CborValue value = validity.get(key).orElse(null);
        if (value == null && !required) {
            return null;
        }
        if (!(value instanceof CborValue.Tagged tagged) || tagged.tag() != TAG_TDATE
                || !(tagged.content() instanceof CborValue.Text text)) {
            throw invalid("MSO validityInfo." + key + " is not a tdate");
        }
        try {
            return OffsetDateTime.parse(text.value(), DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
        } catch (final DateTimeParseException e) {
            throw invalid("MSO validityInfo." + key + " is not an RFC 3339 date-time");
        }
    }

    /**
     * The MSO {@code status}: null only when there is no {@code status} member at all; {@link StatusList} when it holds
     * a {@code status_list}; otherwise {@link NotEvaluable}. Each known member is checked structurally first.
     */
    private static Status status(final CborValue value) {
        if (value == null) {
            return null;
        }
        if (!(value instanceof CborValue.Dict status)) {
            throw invalid("MSO status is not a map");
        }
        final CborValue identifierList = status.get("identifier_list").orElse(null);
        if (identifierList != null) {
            if (!(identifierList instanceof CborValue.Dict ids) || !(ids.get("id").orElse(null) instanceof CborValue.Bytes)
                    || !(ids.get("uri").orElse(null) instanceof CborValue.Text idsUri) || idsUri.value().isBlank()) {
                throw invalid("MSO status.identifier_list is malformed");
            }
            certificate(ids, "identifier_list");
        }
        final CborValue statusList = status.get("status_list").orElse(null);
        if (statusList == null) {
            final List<String> mechanisms = new ArrayList<>();
            for (final CborValue key : status.entries().keySet()) {
                mechanisms.add(key instanceof CborValue.Text t ? t.value() : String.valueOf(((CborValue.Int) key).value()));
            }
            return new NotEvaluable(mechanisms);
        }
        if (!(statusList instanceof CborValue.Dict list)) {
            throw invalid("MSO status.status_list is malformed");
        }
        if (!(list.get("idx").orElse(null) instanceof CborValue.Int idx) || idx.value() < 0
                || idx.value() > Integer.MAX_VALUE
                || !(list.get("uri").orElse(null) instanceof CborValue.Text uri) || uri.value().isBlank()) {
            throw invalid("MSO status.status_list is malformed");
        }
        return new StatusList(new StatusReference((int) idx.value(), uri.value()), certificate(list, "status_list"));
    }

    /** The optional {@code certificate} bstr of a status mechanism, or null. */
    private static byte[] certificate(final CborValue.Dict mechanism, final String name) {
        final CborValue certificate = mechanism.get("certificate").orElse(null);
        if (certificate == null) {
            return null;
        }
        if (!(certificate instanceof CborValue.Bytes bytes)) {
            throw invalid("MSO status." + name + ".certificate is not a byte string");
        }
        return bytes.value();
    }

    private static WalletVerificationException invalid(final String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, safeDetail);
    }

    /** An unmodifiable digest map whose {@link #get} returns a copy, so a caller cannot change the MSO. */
    private static final class DigestMap extends java.util.AbstractMap<Integer, byte[]> {
        private final Map<Integer, byte[]> digests;

        DigestMap(final Map<Integer, byte[]> digests) {
            this.digests = digests;
        }

        @Override
        public byte[] get(final Object key) {
            final byte[] digest = digests.get(key);
            return digest == null ? null : digest.clone();
        }

        @Override
        public boolean containsKey(final Object key) {
            return digests.containsKey(key);
        }

        @Override
        public java.util.Set<Entry<Integer, byte[]>> entrySet() {
            final java.util.Set<Entry<Integer, byte[]>> entries = new java.util.LinkedHashSet<>();
            digests.forEach((id, digest) -> entries.add(Map.entry(id, digest.clone())));
            return Collections.unmodifiableSet(entries);
        }
    }
}
