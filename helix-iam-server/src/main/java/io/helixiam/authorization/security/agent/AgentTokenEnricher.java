package io.helixiam.authorization.security.agent;

import io.helixiam.authorization.amqp.agent.AgentIdentityDto;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM Agent (NHI): the pure token-issuance rules for an agent-backed client. {@link #denialReason}
 * is the lifecycle gate — a non-{@code ACTIVE} status (SUSPENDED / REVOKED / EXPIRED) or a passed
 * {@code expiresAt} blocks token issuance, so revoking or suspending an agent in the console immediately
 * stops it minting tokens. {@link #claims} stamps the {@code nhi.*} identity onto the access token so a
 * resource server can tell a non-human caller (and which agent / accountable owner) apart from a user.
 *
 * <p>Deliberately Spring-free and side-effect-free: the security-critical decision is unit-tested in
 * isolation, and the values it returns are plain {@code String}/{@code Boolean} (never immutable
 * collections, which the SAS Jackson claim allowlist rejects).
 */
public final class AgentTokenEnricher {

    /** The marker claim flagging a non-human (agent) access token. */
    public static final String CLAIM_NHI = "nhi";

    private AgentTokenEnricher() {
    }

    /**
     * The reason this agent must NOT be issued a token, or {@code null} when it may. An agent is blocked
     * when its status is anything other than {@code ACTIVE}, or when it carries an {@code expiresAt} that
     * has already passed.
     */
    public static String denialReason(final String status, final Long expiresAtMillis, final long nowMillis) {
        if (status != null && !"ACTIVE".equalsIgnoreCase(status)) {
            return "agent is " + status.toLowerCase();
        }
        if (expiresAtMillis != null && expiresAtMillis <= nowMillis) {
            return "agent credential has expired";
        }
        return null;
    }

    /** The {@code nhi.*} claim set for an agent-backed access token. Omits null optional attributes. */
    public static Map<String, Object> claims(final AgentIdentityDto agent) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(CLAIM_NHI, Boolean.TRUE);
        claims.put("agent_id", agent.id());
        if (agent.name() != null) {
            claims.put("agent_name", agent.name());
        }
        if (agent.owner() != null) {
            claims.put("agent_owner", agent.owner());
        }
        if (agent.description() != null) {
            claims.put("agent_purpose", agent.description());
        }
        return claims;
    }

    /** Parse an agent's own least-privilege roles from its comma/whitespace-separated {@code roles} value. */
    public static List<String> rolesFrom(final String csv) {
        final List<String> out = new ArrayList<>();
        if (csv == null) {
            return out;
        }
        for (final String token : csv.split("[,\\s]+")) {
            if (!token.isBlank() && !out.contains(token)) {
                out.add(token);
            }
        }
        return out;
    }

    /**
     * The agent's own REALM roles — the entries with no {@code /} (a plain role name). Client roles are
     * encoded {@code clientId/roleName} and handled by {@link #clientRolesFrom(String)}.
     */
    public static List<String> realmRolesFrom(final String csv) {
        final List<String> out = new ArrayList<>();
        for (final String token : rolesFrom(csv)) {
            if (token.indexOf('/') < 0) {
                out.add(token);
            }
        }
        return out;
    }

    /**
     * The agent's own CLIENT roles, grouped by client id. Entries are encoded {@code clientId/roleName}
     * (split on the first {@code /}); a role lands in {@code resource_access.{clientId}.roles}. De-duplicated,
     * insertion-ordered (mutable collections only — the SAS Jackson allowlist rejects immutable ones).
     */
    public static Map<String, List<String>> clientRolesFrom(final String csv) {
        final Map<String, List<String>> out = new LinkedHashMap<>();
        for (final String token : rolesFrom(csv)) {
            final int slash = token.indexOf('/');
            if (slash <= 0 || slash >= token.length() - 1) {
                continue;
            }
            final String clientId = token.substring(0, slash);
            final String role = token.substring(slash + 1);
            final List<String> roles = out.computeIfAbsent(clientId, k -> new ArrayList<>());
            if (!roles.contains(role)) {
                roles.add(role);
            }
        }
        return out;
    }

    /**
     * Union an agent's CLIENT roles into the token's {@code resource_access.{clientId}.roles} — the standard
     * client-role claim — ON TOP of whatever the bound client's service account already granted. Additive per
     * client, de-duplicated, MUTABLE collections only. No-op when there are no client roles; creates
     * {@code resource_access} (and the per-client entry) when absent.
     */
    @SuppressWarnings("unchecked")
    public static void mergeClientRoles(final Map<String, Object> claims,
                                        final Map<String, List<String>> clientRoles) {
        if (clientRoles == null || clientRoles.isEmpty()) {
            return;
        }
        final Object existing = claims.get("resource_access");
        final Map<String, Object> resourceAccess = existing instanceof Map
                ? new LinkedHashMap<>((Map<String, Object>) existing) : new LinkedHashMap<>();
        for (final Map.Entry<String, List<String>> entry : clientRoles.entrySet()) {
            final Object existingClient = resourceAccess.get(entry.getKey());
            final Map<String, Object> client = existingClient instanceof Map
                    ? new LinkedHashMap<>((Map<String, Object>) existingClient) : new LinkedHashMap<>();
            final Object existingRoles = client.get("roles");
            final List<String> roles = existingRoles instanceof List
                    ? new ArrayList<>((List<String>) existingRoles) : new ArrayList<>();
            for (final String role : entry.getValue()) {
                if (!roles.contains(role)) {
                    roles.add(role);
                }
            }
            client.put("roles", roles);
            resourceAccess.put(entry.getKey(), client);
        }
        claims.put("resource_access", resourceAccess);
    }

    /**
     * Union an agent's own roles into the token's {@code realm_access.roles} (the standard realm-role claim),
     * de-duplicated, using MUTABLE collections only (the SAS Jackson claim allowlist rejects immutable ones).
     * No-op when there are no agent roles; creates {@code realm_access} when absent. The agent's grant is
     * ADDED to — never replaces — whatever the bound client's service account already contributed.
     */
    @SuppressWarnings("unchecked")
    public static void mergeRealmRoles(final Map<String, Object> claims, final List<String> agentRoles) {
        if (agentRoles == null || agentRoles.isEmpty()) {
            return;
        }
        final Object existing = claims.get("realm_access");
        final Map<String, Object> realmAccess = existing instanceof Map
                ? new LinkedHashMap<>((Map<String, Object>) existing) : new LinkedHashMap<>();
        final Object existingRoles = realmAccess.get("roles");
        final List<String> roles = existingRoles instanceof List
                ? new ArrayList<>((List<String>) existingRoles) : new ArrayList<>();
        for (final String role : agentRoles) {
            if (!roles.contains(role)) {
                roles.add(role);
            }
        }
        realmAccess.put("roles", roles);
        claims.put("realm_access", realmAccess);
    }
}
