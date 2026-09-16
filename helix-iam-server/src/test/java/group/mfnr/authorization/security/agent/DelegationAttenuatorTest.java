package group.mfnr.authorization.security.agent;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Helix IAM Agent (NHI) delegation (Phase B): the pure attenuation rules for on-behalf-of. Effective
 * authority is the INTERSECTION of the acting user's roles, the agent's own leash, and (when narrowed) the
 * requested roles — never a union, never the owner's roles. Kept Spring-free so the security-critical
 * intersection is unit-tested in isolation from the RFC 8693 exchange.
 */
class DelegationAttenuatorTest {

    @Test
    void effectiveRoles_isTheIntersectionOfUserAndAgentLeash() {
        final List<String> eff = DelegationAttenuator.effectiveRoles(
                List.of("invoices:read", "invoices:write", "hr:read"),  // what BOB can do
                List.of("invoices:read", "invoices:write"),             // the agent's leash (its own roles)
                List.of());                                             // no explicit request → user ∩ agent
        assertEquals(List.of("invoices:read", "invoices:write"), eff);  // hr:read dropped (agent not allowed)
    }

    @Test
    void requestedRoles_narrowFurther_butCannotAddWhatIsntGranted() {
        final List<String> eff = DelegationAttenuator.effectiveRoles(
                List.of("invoices:read", "invoices:write"),
                List.of("invoices:read", "invoices:write"),
                List.of("invoices:read", "admin"));                     // asks for admin too
        assertEquals(List.of("invoices:read"), eff);                    // only the granted intersection survives
    }

    @Test
    void emptyAgentLeash_yieldsNoDelegatedAuthority() {
        // Secure by default: an agent with no roles of its own gets NO authority when acting for a user.
        assertTrue(DelegationAttenuator.effectiveRoles(List.of("invoices:read"), List.of(), List.of()).isEmpty());
    }

    @Test
    void actClaim_namesTheAgentAsActor() {
        final Map<String, Object> act = DelegationAttenuator.actClaim("billing-bot", null);
        assertEquals("billing-bot", act.get("sub"));
        assertNull(act.get("act"), "no nested actor for a single-hop delegation");
    }

    @Test
    void actClaim_nestsThePriorActor_forDelegationChains() {
        final Map<String, Object> inner = DelegationAttenuator.actClaim("billing-bot", null);
        final Map<String, Object> outer = DelegationAttenuator.actClaim("sub-agent", inner);
        assertEquals("sub-agent", outer.get("sub"));
        assertEquals(inner, outer.get("act"), "the chain is represented as nested act claims (agent→sub-agent)");
    }
}
