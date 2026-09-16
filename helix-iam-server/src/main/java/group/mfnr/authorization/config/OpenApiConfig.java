package group.mfnr.authorization.config;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * springdoc-openapi configuration for the Helix IAM publisher.
 *
 * <p><b>Scope:</b> the generated spec documents the realm-admin management API ({@code /admin/**}) ONLY.
 * The Spring Authorization Server hot path ({@code /oauth2/**}, {@code /.well-known/**}, {@code /connect/**},
 * {@code /saml/**}) is deliberately excluded — those endpoints belong to the SAS {@code @Order(1)} filter
 * chain, are described by the OIDC discovery / SAML metadata documents, and must not be re-described or
 * touched here. springdoc's springmvc auto-config only introspects {@code @RequestMapping} handlers, so it
 * never interferes with the SAS filter chain; the {@link GroupedOpenApi} path matcher below additionally
 * pins the visible surface to {@code /admin/**}.
 *
 * <p>Swagger UI is served at {@code /swagger-ui.html} and the raw spec for this group at
 * {@code /v3/api-docs/admin} (the aggregate at {@code /v3/api-docs}). Those paths must be permitted in
 * {@code SecurityConfig} (dev).
 */
@Configuration
public class OpenApiConfig {

    /** Top-level API metadata (title/version/description) shown in Swagger UI. */
    @Bean
    public OpenAPI helixAdminOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Helix IAM Admin API")
                        .version("v1")
                        .description("""
                                Management REST API for the Helix IAM (KubeDNA authorization server) admin \
                                console. Covers per-realm administration of users, roles, organizations, \
                                provisioning and related resources under /admin/realms/{realmId}/**. \
                                The OAuth2/OIDC and SAML protocol endpoints are NOT part of this spec; \
                                use the realm's OIDC discovery document and SAML metadata for those.""")
                        .contact(new Contact().name("Helix IAM").email("m.marzgioui@gmail.com"))
                        .license(new License().name("Proprietary")))
                .externalDocs(new ExternalDocumentation()
                        .description("Helix IAM admin console")
                        .url("/"));
    }

    /**
     * The single published group, pinned to the admin management API. {@code pathsToMatch = /admin/**}
     * guarantees the SAS protocol endpoints never appear in the spec even if springdoc could otherwise
     * see them.
     */
    @Bean
    public GroupedOpenApi adminApiGroup() {
        return GroupedOpenApi.builder()
                .group("admin")
                .pathsToMatch("/admin/**")
                .build();
    }
}
