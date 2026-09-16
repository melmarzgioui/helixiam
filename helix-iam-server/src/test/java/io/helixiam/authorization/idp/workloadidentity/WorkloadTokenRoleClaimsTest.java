package io.helixiam.authorization.idp.workloadidentity;

import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM WIF: a workload token now carries the bound client's service-account roles, exactly like a
 * {@code client_credentials} token — realm roles under {@code realm_access.roles}, client roles under
 * {@code resource_access.<clientId>.roles}. {@link WorkloadIdentityTokenController#roleClaims} maps the
 * resolved service-account grants into those claim blocks.
 */
class WorkloadTokenRoleClaimsTest {

    private ServiceAccountRoleDto role(final String name, final String type, final String roleClientId) {
        return new ServiceAccountRoleDto("id", "apps", "billing-service", name, type, roleClientId);
    }

    @Test
    void noRolesYieldsNoRoleClaims() {
        assertThat(WorkloadIdentityTokenController.roleClaims(List.of())).isEmpty();
        assertThat(WorkloadIdentityTokenController.roleClaims(null)).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void realmRolesGoUnderRealmAccess() {
        final Map<String, Object> claims = WorkloadIdentityTokenController.roleClaims(
                List.of(role("ledger-writer", "REALM", null), role("auditor", "REALM", null)));

        final Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
        assertThat((List<String>) realmAccess.get("roles")).containsExactlyInAnyOrder("ledger-writer", "auditor");
        assertThat(claims).doesNotContainKey("resource_access");
    }

    @Test
    @SuppressWarnings("unchecked")
    void clientRolesGoUnderResourceAccess() {
        final Map<String, Object> claims = WorkloadIdentityTokenController.roleClaims(
                List.of(role("read", "CLIENT", "orders-api")));

        final Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
        final Map<String, Object> ordersApi = (Map<String, Object>) resourceAccess.get("orders-api");
        assertThat((List<String>) ordersApi.get("roles")).containsExactly("read");
    }
}
