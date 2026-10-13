/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.mdoc.CborLimits;
import io.helixiam.authorization.federation.wallet.mdoc.CborValue;
import io.helixiam.authorization.federation.wallet.mdoc.CoseSign1;
import io.helixiam.authorization.federation.wallet.mdoc.StrictCbor;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.federation.wallet.trust.ValidatedChain;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * The CWT form of a Status List Token (draft-ietf-oauth-status-list-21 §5.2, the ISO mdoc form), split out of
 * {@link StatusListToken}, which keeps the JWT form and the checks common to both ({@code sub}, {@code iat},
 * {@code bits}, inflation).
 *
 * <p>COSE_Sign1_Tagged (18), decoded with {@link StrictCbor}, parsed and verified by {@link CoseSign1} (the wallet's
 * one COSE_Sign1 verifier); protected header {@code 1} (alg ES256 -7 / -9, ES384 -35, ES512 -36), {@code 16} (type, the
 * text {@code application/statuslist+cwt}) and {@code 33} (x5chain, which the ISO draft requires in the protected
 * header for the MSO revocation list; it is not read from the unprotected header); payload {@code 2} sub, {@code 6}
 * iat, {@code 4} exp, {@code 65534} ttl, {@code 65533} StatusList {@code {"bits", "lst"}}. The signer chain is
 * validated by {@link IssuerTrustValidator} against the credential's own {@link TrustAnchors} at {@code now}.
 */
final class StatusListCwt {

    private static final String CWT_TYPE = "application/statuslist+cwt";
    /** CBOR budget for a whole CWT: the body is capped at 1 MB before it gets here. */
    private static final CborLimits CWT_LIMITS = new CborLimits(16, 10_000, 1024 * 1024);

    private static final long COSE_HEADER_TYPE = 16;
    /** ES256 -7 (and its fully-specified twin ESP256 -9, HAIP §7), ES384 -35, ES512 -36. */
    private static final Set<Integer> CWT_ALGORITHMS = Set.of(CoseSign1.ES256, CoseSign1.ESP256, CoseSign1.ES384,
            CoseSign1.ES512);
    private static final long CWT_SUB = 2;
    private static final long CWT_EXP = 4;
    private static final long CWT_IAT = 6;
    private static final long CWT_STATUS_LIST = 65533;
    private static final long CWT_TTL = 65534;

    private StatusListCwt() {
    }

    /** Parses and verifies a Status List Token in CWT form (COSE_Sign1_Tagged). */
    static StatusListToken parse(final byte[] cwt, final TrustAnchors anchors, final Instant now,
            final IssuerTrustValidator trust) {
        // COSE_Sign1_Tagged only: untagged and COSE_Mac0 (17) are refused
        if (!(StrictCbor.decode(cwt, CWT_LIMITS) instanceof CborValue.Tagged tagged) || tagged.tag() != 18) {
            throw StatusListToken.invalid("Status List Token is not a COSE_Sign1_Tagged");
        }
        final CoseSign1 cose = CoseSign1.decode(tagged);
        final byte[] payload = cose.payload();
        if (payload == null) {
            throw StatusListToken.invalid("Status List Token is not a COSE_Sign1_Tagged");
        }
        if (!(cose.protectedParameters().get(COSE_HEADER_TYPE).orElse(null) instanceof CborValue.Text type)
                || !CWT_TYPE.equalsIgnoreCase(type.value())) {
            throw new WalletVerificationException(WalletErrorCode.UNSUPPORTED_FORMAT,
                    "Status List Token type is not application/statuslist+cwt");
        }
        if (!CWT_ALGORITHMS.contains(cose.algorithm())) {
            throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                    "Status List Token COSE alg is not allowed");
        }
        final ValidatedChain chain = trust.validateChain(cose.protectedX5chain(), anchors, now);
        final X509Certificate leaf = chain.leaf();
        if (!cose.verify(leaf.getPublicKey(), null, CWT_ALGORITHMS)) {
            throw StatusListToken.signatureInvalid();
        }

        if (!(StrictCbor.decode(payload, CWT_LIMITS) instanceof CborValue.Dict claims)) {
            throw StatusListToken.invalid("Status List Token payload is not a map");
        }
        final String sub = claims.get(CWT_SUB).orElse(null) instanceof CborValue.Text t ? t.value() : null;
        final Instant iat = cborDate(claims.get(CWT_IAT).orElse(null), "iat");
        final Instant exp = cborDate(claims.get(CWT_EXP).orElse(null), "exp");
        final CborValue ttlValue = claims.get(CWT_TTL).orElse(null);
        final Duration ttl = ttlValue == null ? null
                : StatusListToken.ttl(ttlValue instanceof CborValue.Int i ? (Object) i.value() : null);
        if (!(claims.get(CWT_STATUS_LIST).orElse(null) instanceof CborValue.Dict statusList)
                || !(statusList.get("bits").orElse(null) instanceof CborValue.Int bitsValue)
                || !(statusList.get("lst").orElse(null) instanceof CborValue.Bytes lst)) {
            throw StatusListToken.invalid("Status List Token status list is malformed");
        }
        return StatusListToken.build(sub, iat, exp, ttl, bitsValue.value(), lst.value(), now, chain);
    }

    private static Instant cborDate(final CborValue value, final String name) {
        if (value == null) {
            return null;
        }
        if (value instanceof CborValue.Int i) {
            return StatusListToken.numericDate(i.value(), name);
        }
        if (value instanceof CborValue.Real r) {
            return StatusListToken.numericDate(r.value(), name);
        }
        throw StatusListToken.invalid("Status List Token " + name + " is not a NumericDate");
    }
}
