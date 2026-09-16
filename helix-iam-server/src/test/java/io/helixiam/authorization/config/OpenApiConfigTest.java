package io.helixiam.authorization.config;

import org.junit.jupiter.api.Test;
import org.springdoc.core.models.GroupedOpenApi;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit test (no Spring context): the GroupedOpenApi bean builds, names the group "admin",
 * and pins the documented surface to /admin/** — so the SAS OAuth2/OIDC + SAML endpoints can
 * never leak into the spec. Also checks the top-level info metadata is populated.
 */
class OpenApiConfigTest {

    private final OpenApiConfig config = new OpenApiConfig();

    @Test
    void adminGroupIsScopedToAdminPaths() {
        final GroupedOpenApi group = config.adminApiGroup();

        assertThat(group.getGroup()).isEqualTo("admin");
        assertThat(group.getPathsToMatch()).containsExactly("/admin/**");
        // Nothing under /oauth2 or /saml is in scope.
        assertThat(group.getPathsToMatch()).noneMatch(p -> p.contains("oauth2") || p.contains("saml"));
    }

    @Test
    void apiInfoIsPopulated() {
        final var info = config.helixAdminOpenApi().getInfo();

        assertThat(info.getTitle()).isEqualTo("Helix IAM Admin API");
        assertThat(info.getVersion()).isEqualTo("v1");
        assertThat(info.getDescription()).contains("/admin/realms/{realmId}");
    }
}
