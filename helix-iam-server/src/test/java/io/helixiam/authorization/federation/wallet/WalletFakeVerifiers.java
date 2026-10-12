/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.security.audit.AuditLog;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Task 23: a cross-package seam for {@code io.helixiam.e2e.WalletAcceptanceE2eTest} to build the same
 * "real pipeline, fake content check" {@link WalletIdentityProvider} that {@code WalletAuditE2eTest} builds for
 * itself with {@link WalletIdentityProvider}'s package-private constructor. Used only for {@code CREDENTIAL_REVOKED}
 * — every other §15 rejection row is driven with a genuinely malformed presentation through the real verifier instead
 * (see {@code WalletAcceptanceE2eTest}'s own tampering helpers); revocation needs a reachable status-list host this
 * shared e2e context does not stand up, so the same substitution {@code WalletAuditE2eTest} already relies on is
 * reused here, over real HTTP rather than a direct {@code WalletResponseHandler.handle} call.
 */
public final class WalletFakeVerifiers {

    private WalletFakeVerifiers() {
    }

    /** Always throws {@code code} for {@code format} — everything else (claim/decrypt/DCQL/fail/audit) stays real. */
    private record ThrowingVerifier(String fmt, WalletErrorCode code) implements PresentationVerifier {
        @Override
        public String format() {
            return fmt;
        }

        @Override
        public VerifiedPresentation verify(final String rawPresentation, final VerificationContext context) {
            throw new WalletVerificationException(code, "test: forced " + code);
        }
    }

    /** The same provider as {@code real}, every configured format's verifier swapped for one that always throws {@code code}. */
    public static WalletIdentityProvider withThrowingVerifier(final WalletIdentityProvider real,
                                                              final WalletErrorCode code, final AuditLog audit) {
        final Map<String, PresentationVerifier> verifiers = new LinkedHashMap<>();
        for (final String format : real.verifiers().keySet()) {
            verifiers.put(format, new ThrowingVerifier(format, code));
        }
        return new WalletIdentityProvider(real.config(), real.keyRealm(), real.signingKey(), real.trustAnchors(),
                real.statusPolicy(), real.statusClient(), verifiers, real.transactions(), Clock.systemUTC(), audit);
    }

    /**
     * The same provider as {@code real}, its transaction store swapped for {@code store} — used to drive the §15
     * "expired transaction" row (a spy whose {@code complete} returns {@code false}, simulating the TTL winning the
     * race between the response being verified and the transaction completing) over real HTTP.
     */
    public static WalletIdentityProvider withTransactionStore(final WalletIdentityProvider real,
                                                               final WalletTransactionStore store,
                                                               final AuditLog audit) {
        return new WalletIdentityProvider(real.config(), real.keyRealm(), real.signingKey(), real.trustAnchors(),
                real.statusPolicy(), real.statusClient(), real.verifiers(), store, Clock.systemUTC(), audit);
    }
}
