package io.helixiam.authorization.idp.mcp;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM Agent Phase C (MCP auth): serves the <b>RFC 9728 Protected Resource Metadata</b> at
 * {@code /realms/{realm}/.well-known/oauth-protected-resource}. The {@link io.helixiam.authorization.security.realm.RealmRoutingFilter}
 * strips the realm prefix into the (virtual) context path, so this flat mapping is reached per realm and
 * the derived issuer comes out realm-prefixed (matching the OIDC discovery {@code issuer}).
 *
 * <p>By default it advertises the realm itself as the protected resource, guarded by the realm's
 * authorization server. Pass {@code ?resource=<uri>} and Helix hosts the metadata <i>on behalf of</i> a
 * downstream resource (e.g. an MCP server) that delegates its discovery document to Helix — the MCP server
 * then answers an unauthenticated call with
 * {@code WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource?resource=<its-uri>"}.
 */
@RestController
public class ProtectedResourceMetadataController {

    /** Human documentation link surfaced in the metadata (RFC 9728 {@code resource_documentation}). */
    private static final String DOCS = "https://helixiam.com/docs/integration/mcp";

    /** Scopes Helix advertises for MCP resources by default — the OIDC base plus an MCP tool-call scope. */
    private static final List<String> DEFAULT_SCOPES = List.of("openid", "mcp:tools");

    @GetMapping(value = "/.well-known/oauth-protected-resource", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> protectedResourceMetadata(
            @RequestParam(name = "resource", required = false) final String resource) {
        final String issuer = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
        final String res = (resource != null && !resource.isBlank()) ? resource : issuer;
        return ProtectedResourceMetadata.build(res, List.of(issuer), DEFAULT_SCOPES, DOCS);
    }
}
