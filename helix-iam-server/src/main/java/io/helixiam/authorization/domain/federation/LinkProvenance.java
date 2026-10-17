/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import java.util.Locale;
import java.util.Set;

/**
 * Round 6: how a federated link was created. A link to an administrator is honoured at sign-in only when the
 * administrator made it themselves or a realm admin vouched for it: {@link #JIT} (the account was created by that
 * sign-in), {@link #SELF} (linked from the account console after a fresh sign-in), {@link #WALLET} (the account
 * console's wallet linking), {@link #ADMIN_CONFIRMED} (confirmed by a realm admin) or {@link #LEGACY} (existed before
 * the upgrade to rc.12, when it already signed its user in; reported at start-up). {@link #AUTO} links (made by
 * matching a verified e-mail address) and links of unknown origin are refused for administrators.
 */
public final class LinkProvenance {

    public static final String JIT = "JIT";
    public static final String AUTO = "AUTO";
    public static final String SELF = "SELF";
    public static final String WALLET = "WALLET";
    public static final String LEGACY = "LEGACY";
    public static final String ADMIN_CONFIRMED = "ADMIN_CONFIRMED";
    /**
     * Stored by V86 for a pre-upgrade link whose realm the migration could not tell (its provider may come from the
     * realm config folder, loaded only at start-up). Never trusted; {@code UnresolvedLinkReconciler} turns it into
     * {@link #LEGACY} or {@link #AUTO} once the providers are loaded.
     */
    public static final String UNRESOLVED = "UNRESOLVED";

    /** The provenances an administrator's link may have. */
    public static final Set<String> TRUSTED = Set.of(JIT, SELF, WALLET, LEGACY, ADMIN_CONFIRMED);

    private LinkProvenance() {
    }

    /** The stored form; anything unknown becomes {@link #AUTO}. */
    public static String normalize(final String via) {
        if (via == null) {
            return AUTO;
        }
        final String v = via.trim().toUpperCase(Locale.ROOT);
        return TRUSTED.contains(v) ? v : AUTO;
    }

    /** Whether a link of this provenance may sign in an administrator. */
    public static boolean mayAuthenticateAdmin(final String via) {
        return TRUSTED.contains(normalize(via));
    }
}
