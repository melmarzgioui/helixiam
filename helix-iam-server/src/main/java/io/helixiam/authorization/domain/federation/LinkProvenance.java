/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import java.util.Locale;
import java.util.Set;

/**
 * Round 6: how a federated link was created. A link to an administrator is honoured at sign-in only when the
 * administrator made it themselves: {@link #JIT} (the account was created by that sign-in), {@link #SELF} (linked from
 * the account console) or {@link #WALLET} (the account console's wallet linking). {@link #AUTO} links (made by
 * matching a verified e-mail address) and links of unknown origin are refused for administrators.
 */
public final class LinkProvenance {

    public static final String JIT = "JIT";
    public static final String AUTO = "AUTO";
    public static final String SELF = "SELF";
    public static final String WALLET = "WALLET";

    /** The provenances an administrator's link may have. */
    public static final Set<String> SELF_MADE = Set.of(JIT, SELF, WALLET);

    private LinkProvenance() {
    }

    /** The stored form; anything unknown becomes {@link #AUTO}. */
    public static String normalize(final String via) {
        if (via == null) {
            return AUTO;
        }
        final String v = via.trim().toUpperCase(Locale.ROOT);
        return SELF_MADE.contains(v) ? v : AUTO;
    }

    /** Whether a link of this provenance may sign in an administrator. */
    public static boolean mayAuthenticateAdmin(final String via) {
        return SELF_MADE.contains(normalize(via));
    }
}
