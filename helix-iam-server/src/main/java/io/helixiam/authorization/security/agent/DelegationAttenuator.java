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
