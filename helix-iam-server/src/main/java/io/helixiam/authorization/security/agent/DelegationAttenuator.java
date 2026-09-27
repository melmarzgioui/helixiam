/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.agent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM Agent (NHI) delegation — the pure attenuation rules for on-behalf-of (Phase B, RFC 8693).
 *
 * <p>When an agent acts <em>for</em> a user, the token's effective authority is the {@link #effectiveRoles
 * INTERSECTION} of three sets — the acting user's roles, the agent's own leash (its per-agent roles), and
 * (when present) the roles requested for this exchange. Never a union; never the owner's roles. Authority
 * can only shrink. {@link #actClaim} builds the {@code act} actor claim (nested for agent→sub-agent chains)
 * so a resource server can see both <em>who</em> the token is for ({@code sub}=user) and <em>what</em>
 * acted ({@code act.sub}=agent).
 *
 * <p>Spring-free and side-effect-free; returns MUTABLE collections only (the SAS Jackson claim allowlist
 * rejects immutable ones).
 */
public final class DelegationAttenuator {

    private DelegationAttenuator() {
    }

    /**
     * The effective delegated roles: {@code user ∩ agentLeash}, further narrowed by {@code requested} when
     * that list is non-empty. Order follows the user's roles. An empty agent leash yields no authority
     * (secure by default — an agent must be explicitly granted roles to act for a user).
     */
    public static List<String> effectiveRoles(final List<String> userRoles, final List<String> agentLeash,
                                              final List<String> requested) {
        final List<String> user = userRoles == null ? List.of() : userRoles;
        final List<String> leash = agentLeash == null ? List.of() : agentLeash;
        final boolean narrow = requested != null && !requested.isEmpty();
        final List<String> out = new ArrayList<>();
        for (final String role : user) {
            if (leash.contains(role) && (!narrow || requested.contains(role)) && !out.contains(role)) {
                out.add(role);
            }
        }
        return out;
    }

    /**
     * The effective delegated roles when the two tokens spell realm roles differently (docs/role-names-in-tokens.md):
     * a token issued for a user carries {@code <role>_<realm>}, a machine (agent {@code client_credentials}) token
     * carries the plain role name. Both sides are compared on the plain name, but only a token in the user form is
     * un-suffixed, so a plain role that happens to end in {@code _<realm>} is never read as another role. The result
     * keeps the subject token's own spelling (the token output format does not change). {@code requested} narrows by
     * either spelling; it can never widen.
     *
     * @param userQualified  whether {@code userRoles} come from a token in the user form
     * @param leashQualified whether {@code agentLeash} comes from a token in the user form (a delegated actor token)
     */
    public static List<String> effectiveRoles(final List<String> userRoles, final boolean userQualified,
                                              final List<String> agentLeash, final boolean leashQualified,
                                              final List<String> requested, final String realm) {
        final List<String> user = userRoles == null ? List.of() : userRoles;
        final java.util.Set<String> leash = new java.util.HashSet<>();
        if (agentLeash != null) {
            agentLeash.forEach(r -> leash.add(plain(r, leashQualified, realm)));
        }
        final boolean narrow = requested != null && !requested.isEmpty();
        final List<String> out = new ArrayList<>();
        for (final String role : user) {
            final String name = plain(role, userQualified, realm);
            if (leash.contains(name) && (!narrow || requested.contains(role) || requested.contains(name))
                    && !out.contains(role)) {
                out.add(role);
            }
        }
        return out;
    }

    /** The plain role name: {@code <role>_<realm>} without its suffix when the token is in the user form. */
    static String plain(final String role, final boolean qualified, final String realm) {
        final String suffix = "_" + realm;
        if (qualified && realm != null && role != null && role.endsWith(suffix) && role.length() > suffix.length()) {
            return role.substring(0, role.length() - suffix.length());
        }
        return role;
    }

    /**
     * The RFC 8693 {@code act} actor claim naming {@code agentSub} as what acted. When {@code priorActor}
     * is non-null it is nested under {@code act} to represent a delegation chain (the caller acted through
     * this agent). Mutable maps only.
     */
    public static Map<String, Object> actClaim(final String agentSub, final Map<String, Object> priorActor) {
        final Map<String, Object> act = new LinkedHashMap<>();
        act.put("sub", agentSub);
        if (priorActor != null) {
            act.put("act", priorActor);
        }
        return act;
    }
}
