/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import java.util.Locale;

/**
 * What {@link WalletSubjectResolver} derived from a verified PID (maintainer decision 1: administrative number, else
 * an explicit link). The subject values are lower-case hex HMAC-SHA256 digests under the realm's pepper, safe to log
 * and to store as a federated link's external subject; they never carry the number or the attributes themselves.
 *
 * <ul>
 *   <li>{@link AdminNumber}: from {@code issuing_country + ":" + personal_administrative_number}. May sign in through
 *       an existing link and, when the realm's {@code AccountLinkingPolicy} allows JIT provisioning, create an
 *       account.</li>
 *   <li>{@link Tuple}: from the normalised attribute tuple. Weak and collision-prone, so it may ONLY sign in through a
 *       link the user created while authenticated; it never creates an account and never auto-links by name or
 *       email.</li>
 *   <li>{@link Unavailable}: no subject; the login fails with {@link WalletErrorCode#SUBJECT_UNAVAILABLE} and
 *       {@link Reason} tells the link page what to explain.</li>
 * </ul>
 */
public sealed interface WalletSubject {

    /** The error code a login without a usable subject reports. */
    default WalletErrorCode errorCode() {
        return WalletErrorCode.SUBJECT_UNAVAILABLE;
    }

    /** Hex HMAC of {@code issuing_country + ":" + personal_administrative_number}. */
    record AdminNumber(String value) implements WalletSubject {
    }

    /** Hex HMAC of the normalised attribute tuple; a link key only. */
    record Tuple(String value) implements WalletSubject {
    }

    /** No usable subject. */
    record Unavailable(Reason reason) implements WalletSubject {
    }

    /** Why no account could be resolved from the wallet; {@link #code()} is the stable UI/audit key. */
    enum Reason {
        /** No administrative number, and the provider does not accept the weak attribute-tuple link fallback
         *  ({@code subject.acknowledgeWeakSubject=false}). */
        WEAK_SUBJECT_NOT_ACKNOWLEDGED,
        /** The provider's subject strategy is not implemented ({@code NONE}, verify-only step-up). */
        STRATEGY_NOT_SUPPORTED,
        /** No administrative number, and the PID lacks a name or the birth date the tuple needs. */
        MISSING_IDENTITY_ATTRIBUTES,
        /** The subject is valid but no account is linked to it, and it may not create one: the user must sign in
         *  another way and link the wallet from the account console. */
        LINK_REQUIRED;

        /** e.g. {@code wallet.subject_unavailable.link_required}. */
        public String code() {
            return WalletErrorCode.SUBJECT_UNAVAILABLE.reason() + "." + name().toLowerCase(Locale.ROOT);
        }
    }
}
