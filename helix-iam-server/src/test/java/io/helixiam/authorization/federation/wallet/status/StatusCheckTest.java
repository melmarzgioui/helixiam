/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link StatusCheck}: the one status-policy decision shared by the SD-JWT VC and mdoc verifiers. */
class StatusCheckTest {

    private static final StatusReference REF = new StatusReference(7, "https://status.example/1");
    private static final TrustAnchors ANCHORS = new TrustAnchors(java.util.Set.of(), List.of(), null);
    private static final io.helixiam.authorization.federation.wallet.testwallet.TestPki PKI =
            io.helixiam.authorization.federation.wallet.testwallet.TestPki.create("Status Check");
    private static final CredentialIssuer ISSUER = new CredentialIssuer(
            new io.helixiam.authorization.federation.wallet.trust.ValidatedChain(
                    PKI.issueLeaf(io.helixiam.authorization.federation.wallet.testwallet.TestPki.LeafSpec.defaults())
                            .chain(), new java.security.cert.TrustAnchor(PKI.root(), null)), null);
    private static final StatusPolicy CLOSED = policy(false, StatusPolicy.OnUnavailable.FAIL_CLOSED);
    private static final StatusPolicy OPEN = policy(false, StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT);

    private static StatusPolicy policy(final boolean required, final StatusPolicy.OnUnavailable onUnavailable) {
        return new StatusPolicy(required, onUnavailable, Duration.ofSeconds(900), List.of());
    }

    private static void assertCode(final ThrowingCallable call, final WalletErrorCode code) {
        assertThatThrownBy(call).isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }

    @Test
    void resultConstants() {
        assertThat(StatusCheck.ABSENT).isEqualTo("ABSENT");
        assertThat(StatusCheck.UNAVAILABLE_ACCEPTED).isEqualTo("UNAVAILABLE_ACCEPTED");
    }

    @Test
    void absentIsAbsentUnlessRequired() {
        assertThat(StatusCheck.absent(CLOSED, "no status")).isEqualTo(StatusCheck.ABSENT);
        assertThat(StatusCheck.absent(null, "no status")).isEqualTo(StatusCheck.ABSENT);
        assertCode(() -> StatusCheck.absent(policy(true, StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT), "x"),
                WalletErrorCode.STATUS_REQUIRED);
    }

    @Test
    void notEvaluableFollowsOnUnavailable() {
        assertCode(() -> StatusCheck.notEvaluable(CLOSED, "x"), WalletErrorCode.STATUS_UNAVAILABLE);
        assertCode(() -> StatusCheck.notEvaluable(null, "x"), WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(StatusCheck.notEvaluable(OPEN, "x")).isEqualTo(StatusCheck.UNAVAILABLE_ACCEPTED);
    }

    @Test
    void evaluatorValidIsValidAndGetsTheReferenceAndAnchors() {
        final AtomicReference<Object[]> seen = new AtomicReference<>();
        assertThat(StatusCheck.evaluate((ref, anchors, issuer) -> {
            seen.set(new Object[] {ref, anchors, issuer});
            return StatusEvaluator.VALID;
        }, REF, ANCHORS, ISSUER, CLOSED)).isEqualTo(StatusEvaluator.VALID);
        assertThat(seen.get()).containsExactly(REF, ANCHORS, ISSUER);
    }

    @Test
    void walletExceptionsPassThroughUnderBothPolicies() {
        for (final StatusPolicy p : List.of(CLOSED, OPEN)) {
            assertCode(() -> StatusCheck.evaluate((ref, a, issuer) -> {
                throw new WalletVerificationException(WalletErrorCode.CREDENTIAL_REVOKED, "revoked");
            }, REF, ANCHORS, ISSUER, p), WalletErrorCode.CREDENTIAL_REVOKED);
        }
    }

    @Test
    void nonValidAnswerIsNeverAccepted() {
        for (final StatusPolicy p : List.of(CLOSED, OPEN)) {
            assertCode(() -> StatusCheck.evaluate((ref, a, issuer) -> "REVOKED", REF, ANCHORS, ISSUER, p),
                    WalletErrorCode.STATUS_UNAVAILABLE);
        }
    }

    @Test
    void nonWalletExceptionFollowsOnUnavailable() {
        final StatusEvaluator broken = (ref, a, issuer) -> {
            throw new IllegalStateException("down");
        };
        assertCode(() -> StatusCheck.evaluate(broken, REF, ANCHORS, ISSUER, CLOSED),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(StatusCheck.evaluate(broken, REF, ANCHORS, ISSUER, OPEN)).isEqualTo(StatusCheck.UNAVAILABLE_ACCEPTED);
    }

    @Test
    void aMissingIssuerIsABugNeverAnAcceptedUnavailableStatus() {
        assertThatThrownBy(() -> StatusCheck.evaluate((ref, a, issuer) -> StatusEvaluator.VALID, REF, ANCHORS, null,
                OPEN)).isInstanceOf(NullPointerException.class);
    }
}
