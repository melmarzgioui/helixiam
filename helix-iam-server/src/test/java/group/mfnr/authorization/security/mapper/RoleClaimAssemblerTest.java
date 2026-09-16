package group.mfnr.authorization.security.mapper;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * role namespacing: realm roles under {@code realm_access.roles}, client roles under
 * {@code resource_access.<clientId>.roles} — never flattened into a single ambiguous list.
 */
class RoleClaimAssemblerTest {

    private static final String RA = "realm_access";
    private static final String RES = "resource_access";

    @SuppressWarnings("unchecked")
    private static List<String> realmRoles(final Map<String, Object> claims) {
        return (List<String>) ((Map<String, Object>) claims.get(RA)).get("roles");
    }

    @SuppressWarnings("unchecked")
    private static List<String> clientRoles(final Map<String, Object> claims, final String clientId) {
        final Map<String, Object> res = (Map<String, Object>) claims.get(RES);
        return (List<String>) ((Map<String, Object>) res.get(clientId)).get("roles");
    }

    @Test
    void splitsRealmAndClientRoles_intoKeycloakNamespaces() {
        final Map<String, Object> claims = RoleClaimAssembler.assemble(
                Set.of("fleet-operator"),
                List.of(new RoleClaimAssembler.TypedRole("test", "CLIENT", "svc-short")));

        assertEquals(List.of("fleet-operator"), realmRoles(claims));
        assertEquals(List.of("test"), clientRoles(claims, "svc-short"));
    }

    @Test
    void serviceAccountRealmRole_landsUnderRealmAccess() {
        final Map<String, Object> claims = RoleClaimAssembler.assemble(
                Set.of(),
                List.of(new RoleClaimAssembler.TypedRole("fleet-operator", "REALM", null)));

        assertEquals(List.of("fleet-operator"), realmRoles(claims));
        assertFalse(claims.containsKey(RES), "no client roles → no resource_access key");
    }

    @Test
    void groupsMultipleClientRoles_underTheirClient_sortedAndDeduped() {
        final Map<String, Object> claims = RoleClaimAssembler.assemble(
                Set.of("admin"),
                List.of(
                        new RoleClaimAssembler.TypedRole("writer", "CLIENT", "app-a"),
                        new RoleClaimAssembler.TypedRole("reader", "CLIENT", "app-a"),
                        new RoleClaimAssembler.TypedRole("reader", "CLIENT", "app-a"),
                        new RoleClaimAssembler.TypedRole("ops", "CLIENT", "app-b")));

        assertEquals(List.of("admin"), realmRoles(claims));
        assertEquals(List.of("reader", "writer"), clientRoles(claims, "app-a"), "sorted within a client");
        assertEquals(List.of("ops"), clientRoles(claims, "app-b"));
    }

    @Test
    void emptyInput_stillEmitsRealmAccessWithEmptyRoles() {
        final Map<String, Object> claims = RoleClaimAssembler.assemble(Set.of(), List.of());

        assertTrue(realmRoles(claims).isEmpty(), "realm_access.roles is always present (possibly empty)");
        assertFalse(claims.containsKey(RES));
    }

    @Test
    void clientRoleWithNoClientId_fallsBackToRealmAccess() {
        // A malformed CLIENT role lacking a client id must not be silently dropped — keep it visible.
        final Map<String, Object> claims = RoleClaimAssembler.assemble(
                Set.of(),
                List.of(new RoleClaimAssembler.TypedRole("orphan", "CLIENT", null)));

        assertEquals(List.of("orphan"), realmRoles(claims));
    }
}
