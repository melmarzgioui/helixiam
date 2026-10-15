/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.util.Objects;

/**
 * A trusted list that could not be loaded. The message is safe to log, audit and show to an admin: it never carries
 * list content, certificate bytes or a parser's own message (which may quote the input).
 */
public class TrustedListException extends Exception {

    /** Why. */
    public enum Kind {
        /** No answer: connect, TLS, timeout or an HTTP status other than 200. */
        FETCH,
        /** The server answered with a redirect; redirects are not followed. */
        REDIRECT,
        /** The list is larger than the size cap. */
        TOO_LARGE,
        /** Not a well-formed, acceptable document (a DOCTYPE, too deep, not the expected structure). */
        MALFORMED,
        /** The signature is missing, invalid, does not cover the whole list, or is not by a pinned signer. */
        SIGNATURE,
        /** The pinned signer certificate was not valid when the list was issued. */
        SIGNER,
        /** The list's NextUpdate has passed, or it has none (a closed list). */
        EXPIRED,
        /** The sequence number is lower than that of the last list accepted. */
        ROLLBACK,
        /** Refused by policy before fetching (not https, blocked by the egress guard, too many pointers). */
        POLICY
    }

    private final Kind kind;

    public TrustedListException(final Kind kind, final String message) {
        super(message, null, false, false);
        this.kind = Objects.requireNonNull(kind, "kind");
    }

    public Kind kind() {
        return kind;
    }
}
