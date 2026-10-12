/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;

/**
 * Resolves a credential's Token Status List reference (draft-ietf-oauth-status-list §6.2) to its status. Implemented
 * by the status-list client (Task 10); the presentation verifiers depend only on this interface.
 *
 * <p>Contract (fail closed): return {@link #VALID} only when the referenced status is {@code VALID}; otherwise throw a
 * {@link io.helixiam.authorization.federation.wallet.WalletVerificationException} ({@code CREDENTIAL_REVOKED},
 * {@code CREDENTIAL_SUSPENDED}, {@code STATUS_UNAVAILABLE}, ...). A caller treats any other return value, and any other
 * exception, as {@code STATUS_UNAVAILABLE}.
 */
@FunctionalInterface
public interface StatusEvaluator {

    /** The only non-throwing outcome. */
    String VALID = "VALID";

    /**
     * @param ref     the credential's {@code status.status_list} reference
     * @param anchors the wallet provider's trust anchors (the Status List Token must chain to them)
     * @return {@link #VALID}
     */
    String evaluate(StatusReference ref, TrustAnchors anchors);

    /**
     * As {@link #evaluate(StatusReference, TrustAnchors)}, knowing who issued the credential, so an evaluator can bind
     * the list signer to the credential issuer (ISO/IEC 18013-5 §12.3.6, docs/eudi-wallet-spec-notes.md §6.5). The
     * presentation verifiers always call this form. The default ignores {@code issuer}: evaluators without a signer
     * rule (and test lambdas) need not implement it; {@link TokenStatusListClient#cwtEvaluator()} enforces the rule.
     *
     * @param issuer the credential's issuer chain and, for mdoc, the optional {@code status_list.certificate}
     */
    default String evaluate(final StatusReference ref, final TrustAnchors anchors, final CredentialIssuer issuer) {
        return evaluate(ref, anchors);
    }
}
