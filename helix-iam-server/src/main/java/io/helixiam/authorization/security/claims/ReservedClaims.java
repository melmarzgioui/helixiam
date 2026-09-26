/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.claims;

import java.util.Locale;
import java.util.Set;

/**
 * Token claims that carry identity, audience, lifetime, session or authority. Nothing user-controlled — a
 * profile attribute, a protocol mapper, an imported mapper — may ever write one of these: doing so would let a
 * user (or a misconfigured mapper) forge who the token is about, who it is for, or what it may do.
 * {@code sub} can still be changed per client through the admin-configured subject-claim setting.
 */
public final class ReservedClaims {

    public static final Set<String> NAMES = Set.of(
            // JWT / OIDC protocol
            "sub", "iss", "aud", "exp", "iat", "nbf", "jti", "azp", "sid", "auth_time", "nonce", "acr", "amr",
            "at_hash", "c_hash", "s_hash", "typ", "cnf",
            // OAuth authority
            "scope", "scp", "client_id", "roles", "realm_access", "resource_access", "organizations",
            // delegation / non-human identity
            "act", "may_act", "nhi", "agent_id", "agent_name", "agent_scope", "wif", "workload_iss", "workload_sub");

    private ReservedClaims() {
    }

    /** True when {@code name} (trimmed, case-insensitive) is a reserved claim. */
    public static boolean isReserved(final String name) {
        return name != null && NAMES.contains(name.trim().toLowerCase(Locale.ROOT));
    }
}
