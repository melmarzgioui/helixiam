/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;

/**
 * The one credential-status decision shared by every presentation verifier (SD-JWT VC and mdoc), so the fail-open
 * rules cannot drift between formats. Each method returns the {@code VerifiedPresentation.statusResult} value or
 * throws a {@link WalletVerificationException}:
 * <ul>
 *   <li>{@link #absent}: no status at all: {@code STATUS_REQUIRED} when {@code policy.required}, else {@link #ABSENT}
 *       (the only way to {@code ABSENT});</li>
 *   <li>{@link #notEvaluable}: a present status with no evaluable mechanism is <em>unavailable</em>;</li>
 *   <li>{@link #evaluate}: the {@link StatusEvaluator} must answer {@link StatusEvaluator#VALID} or throw; its wallet
 *       exceptions pass through, any other answer is {@code STATUS_UNAVAILABLE} (never fail-open), and a non-wallet
 *       exception is <em>unavailable</em>.</li>
 * </ul>
 * <em>Unavailable</em> is {@code STATUS_UNAVAILABLE} under {@code FAIL_CLOSED} (and a null policy), and accepted as
 * {@link #UNAVAILABLE_ACCEPTED} under {@code FAIL_OPEN_WITH_AUDIT}; the caller must audit that result.
 */
public final class StatusCheck {

    /** No status reference at all. */
    public static final String ABSENT = "ABSENT";
    /** Status could not be evaluated and was accepted under {@code FAIL_OPEN_WITH_AUDIT}. */
    public static final String UNAVAILABLE_ACCEPTED = "UNAVAILABLE_ACCEPTED";

    private StatusCheck() {
    }

    /** The credential carries no status. */
    public static String absent(final StatusPolicy policy, final String safeDetail) {
        if (policy != null && policy.required()) {
            throw new WalletVerificationException(WalletErrorCode.STATUS_REQUIRED, safeDetail);
        }
        return ABSENT;
    }

    /** The credential carries a status that has no mechanism this verifier can evaluate. */
    public static String notEvaluable(final StatusPolicy policy, final String safeDetail) {
        return unavailable(policy, safeDetail);
    }

    /** Evaluates {@code ref} against {@code anchors}. */
    public static String evaluate(final StatusEvaluator evaluator, final StatusReference ref,
            final TrustAnchors anchors, final StatusPolicy policy) {
        return evaluate(evaluator, ref, anchors, null, policy);
    }

    /**
     * Evaluates {@code ref} against {@code anchors} for the credential issued by {@code issuer} (the presentation
     * verifiers' form, see {@link StatusEvaluator#evaluate(StatusReference, TrustAnchors, CredentialIssuer)}); a null
     * {@code issuer} calls the issuer-less form.
     */
    public static String evaluate(final StatusEvaluator evaluator, final StatusReference ref,
            final TrustAnchors anchors, final CredentialIssuer issuer, final StatusPolicy policy) {
        final String result;
        try {
            result = issuer == null ? evaluator.evaluate(ref, anchors) : evaluator.evaluate(ref, anchors, issuer);
        } catch (final WalletVerificationException e) {
            throw e;
        } catch (final RuntimeException e) {
            return unavailable(policy, "credential status could not be determined");
        }
        if (!StatusEvaluator.VALID.equals(result)) {
            throw new WalletVerificationException(WalletErrorCode.STATUS_UNAVAILABLE,
                    "credential status is not VALID"); // never fail-open
        }
        return result;
    }

    private static String unavailable(final StatusPolicy policy, final String safeDetail) {
        if (policy != null && policy.onUnavailable() == StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT) {
            return UNAVAILABLE_ACCEPTED;
        }
        throw new WalletVerificationException(WalletErrorCode.STATUS_UNAVAILABLE, safeDetail);
    }
}
