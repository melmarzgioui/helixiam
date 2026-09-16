package io.helixiam.authorization.security.agent;

import io.helixiam.authorization.amqp.agent.AgentIdentityDto;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Helix IAM Agent (NHI): the pure token-enrichment rules — the lifecycle gate that decides whether an
 * agent may be issued a token, and the {@code nhi.*} claim set stamped onto it. Kept free of Spring so the
 * security-critical decision is unit-tested in isolation from the OAuth runtime.
 */
class AgentTokenEnricherTest {

    private static final long NOW = 1_700_000_000_000L;

    private static AgentIdentityDto agent(final String status, final Long expiresAt) {
        return new AgentIdentityDto("a-1", "gov", "billing-bot", "Billing bot", "reconciles invoices",
                "alice@gov.example", status, "SECRET", "cac-bot", "openid", true, NOW - 1000, expiresAt, null, null);
    }

    @Test
    void activeAgent_isAllowed() {
        assertNull(AgentTokenEnricher.denialReason("ACTIVE", null, NOW));
    }

    @Test
    void suspendedAndRevokedAndExpiredStatus_areDenied() {
        assertTrue(AgentTokenEnricher.denialReason("SUSPENDED", null, NOW).contains("suspend"));
        assertTrue(AgentTokenEnricher.denialReason("REVOKED", null, NOW).toLowerCase().contains("revok"));
        assertTrue(AgentTokenEnricher.denialReason("EXPIRED", null, NOW) != null);
    }

    @Test
    void pastExpiry_isDenied_evenWhenActive() {
        assertTrue(AgentTokenEnricher.denialReason("ACTIVE", NOW - 1, NOW).toLowerCase().contains("expire"));
    }

    @Test
    void futureExpiry_isAllowed() {
        assertNull(AgentTokenEnricher.denialReason("ACTIVE", NOW + 60_000, NOW));
    }

    @Test
    void rolesFrom_parsesCsvAndWhitespace_andTolleratesNull() {
        assertEquals(java.util.List.of("a", "b", "c"), AgentTokenEnricher.rolesFrom("a, b  c"));
        assertTrue(AgentTokenEnricher.rolesFrom(null).isEmpty());
        assertTrue(AgentTokenEnricher.rolesFrom("   ").isEmpty());
    }

    @Test
    void mergeRealmRoles_unionsIntoExisting_withoutDuplicates() {
        final Map<String, Object> claims = new java.util.HashMap<>();
        final Map<String, Object> realmAccess = new java.util.HashMap<>();
        realmAccess.put("roles", new java.util.ArrayList<>(java.util.List.of("ledger-writer")));
        claims.put("realm_access", realmAccess);

        AgentTokenEnricher.mergeRealmRoles(claims, java.util.List.of("invoices:read", "ledger-writer"));

        @SuppressWarnings("unchecked")
        final java.util.List<String> roles = (java.util.List<String>) ((Map<String, Object>) claims.get("realm_access")).get("roles");
        assertEquals(java.util.List.of("ledger-writer", "invoices:read"), roles);
    }

    @Test
    void mergeRealmRoles_createsRealmAccess_whenAbsent_andNoOpsOnEmpty() {
        final Map<String, Object> claims = new java.util.HashMap<>();
        AgentTokenEnricher.mergeRealmRoles(claims, java.util.List.of("invoices:read"));
        assertTrue(claims.containsKey("realm_access"));

        final Map<String, Object> untouched = new java.util.HashMap<>();
        AgentTokenEnricher.mergeRealmRoles(untouched, java.util.List.of());
        assertTrue(untouched.isEmpty(), "no realm_access is fabricated when there are no agent roles");
    }

    @Test
    void realmRolesFrom_keepsOnlyPlainRoles_andClientRolesFrom_groupsByClient() {
        final String csv = "invoices:read billing-bot-client/ledger:write reports:view billing-bot-client/audit crm/read";
        assertEquals(java.util.List.of("invoices:read", "reports:view"), AgentTokenEnricher.realmRolesFrom(csv));

        final Map<String, java.util.List<String>> byClient = AgentTokenEnricher.clientRolesFrom(csv);
        assertEquals(java.util.List.of("ledger:write", "audit"), byClient.get("billing-bot-client"));
        assertEquals(java.util.List.of("read"), byClient.get("crm"));
    }

    @Test
    void mergeClientRoles_unionsIntoResourceAccess_perClient_withoutDuplicates() {
        final Map<String, Object> claims = new java.util.HashMap<>();
        final Map<String, Object> resourceAccess = new java.util.HashMap<>();
        final Map<String, Object> existingClient = new java.util.HashMap<>();
        existingClient.put("roles", new java.util.ArrayList<>(java.util.List.of("ledger:write")));
        resourceAccess.put("billing-bot-client", existingClient);
        claims.put("resource_access", resourceAccess);

        AgentTokenEnricher.mergeClientRoles(claims, Map.of(
                "billing-bot-client", java.util.List.of("ledger:write", "audit"),
                "crm", java.util.List.of("read")));

        @SuppressWarnings("unchecked")
        final Map<String, Object> ra = (Map<String, Object>) claims.get("resource_access");
        @SuppressWarnings("unchecked")
        final java.util.List<String> billing = (java.util.List<String>) ((Map<String, Object>) ra.get("billing-bot-client")).get("roles");
        assertEquals(java.util.List.of("ledger:write", "audit"), billing);
        @SuppressWarnings("unchecked")
        final java.util.List<String> crm = (java.util.List<String>) ((Map<String, Object>) ra.get("crm")).get("roles");
        assertEquals(java.util.List.of("read"), crm);
    }

    @Test
    void mergeClientRoles_isNoOpOnEmpty() {
        final Map<String, Object> claims = new java.util.HashMap<>();
        AgentTokenEnricher.mergeClientRoles(claims, Map.of());
        assertTrue(claims.isEmpty(), "no resource_access is fabricated when there are no client roles");
    }

    @Test
    void claims_carryTheNhiMarkerAndAgentIdentity() {
        final Map<String, Object> c = AgentTokenEnricher.claims(agent("ACTIVE", null));
        assertEquals(Boolean.TRUE, c.get("nhi"));
        assertEquals("a-1", c.get("agent_id"));
        assertEquals("billing-bot", c.get("agent_name"));
        assertEquals("alice@gov.example", c.get("agent_owner"));
        assertEquals("reconciles invoices", c.get("agent_purpose"));
    }
}
