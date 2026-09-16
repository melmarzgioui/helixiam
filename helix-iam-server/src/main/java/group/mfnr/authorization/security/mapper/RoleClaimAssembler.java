package group.mfnr.authorization.security.mapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Helix IAM: builds role claims so realm roles and client roles stay namespaced instead
 * of flattened into one ambiguous list:
 * <pre>
 *   "realm_access":    { "roles": ["fleet-operator"] },
 *   "resource_access": { "svc-short": { "roles": ["test"] } }
 * </pre>
 * {@code realm_access} is always emitted (possibly with an empty list); {@code resource_access} only when
 * at least one client role exists. Roles are sorted and de-duplicated within each bucket.
 */
public final class RoleClaimAssembler {

    /** A role tagged with whether it is realm- or client-scoped (and, if client, which client owns it). */
    public record TypedRole(String name, String type, String clientId) {
    }

    private RoleClaimAssembler() {
    }

    /**
     * Assembles the {@code realm_access}/{@code resource_access} claim map. {@code realmBaseRoles} are roles
     * already known to be realm-scoped (e.g. a user's {@code user_in_role} grants); {@code typedRoles} are
     * service-account grants tagged REALM or CLIENT. A CLIENT role with no client id falls back to realm
     * scope rather than being dropped.
     */
    public static Map<String, Object> assemble(final Set<String> realmBaseRoles, final List<TypedRole> typedRoles) {
        final Set<String> realm = new TreeSet<>();
        if (realmBaseRoles != null) {
            realm.addAll(realmBaseRoles);
        }
        final Map<String, Set<String>> byClient = new TreeMap<>();
        if (typedRoles != null) {
            for (final TypedRole role : typedRoles) {
                if (role == null || role.name() == null) {
                    continue;
                }
                if ("CLIENT".equalsIgnoreCase(role.type()) && role.clientId() != null && !role.clientId().isBlank()) {
                    byClient.computeIfAbsent(role.clientId(), k -> new TreeSet<>()).add(role.name());
                } else {
                    realm.add(role.name());
                }
            }
        }

        // IMPORTANT: use only mutable java.util collections (HashMap/ArrayList) in token claims — Spring
        // Authorization Server persists the authorization and re-reads it with a Jackson allowlist that
        // REJECTS Map.of()/List.of() (ImmutableCollections$*), which would break logout/refresh/introspect.
        final Map<String, Object> out = new LinkedHashMap<>();
        out.put("realm_access", rolesMap(realm));
        if (!byClient.isEmpty()) {
            final Map<String, Object> resourceAccess = new LinkedHashMap<>();
            byClient.forEach((clientId, roles) -> resourceAccess.put(clientId, rolesMap(roles)));
            out.put("resource_access", resourceAccess);
        }
        return out;
    }

    /** A mutable {@code {"roles": [...]}} map safe for SAS's authorization (de)serialization allowlist. */
    private static Map<String, Object> rolesMap(final Set<String> roles) {
        final Map<String, Object> map = new LinkedHashMap<>();
        map.put("roles", new ArrayList<>(roles));
        return map;
    }
}
