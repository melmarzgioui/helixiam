/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.mcp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Helix IAM Agent Phase C (MCP auth): RFC 9728 OAuth 2.0 Protected Resource Metadata — the document a
 * resource server (e.g. an MCP server) publishes so a client can discover which authorization server
 * protects it. Pure builder, unit-tested in isolation.
 */
class ProtectedResourceMetadataTest {

    @Test
    void build_carriesResource_authorizationServers_andHeaderBearerMethod() {
        final Map<String, Object> m = ProtectedResourceMetadata.build(
                "https://mcp.example",
                List.of("https://helix.example/realms/acme"),
                List.of("openid", "mcp:tools"),
                "https://docs.example/mcp");

        assertEquals("https://mcp.example", m.get("resource"));
        assertEquals(List.of("https://helix.example/realms/acme"), m.get("authorization_servers"));
        assertEquals(List.of("openid", "mcp:tools"), m.get("scopes_supported"));
        // MCP passes the token in the Authorization header — RFC 9728/6750 "header" method.
        assertEquals(List.of("header"), m.get("bearer_methods_supported"));
        assertEquals("https://docs.example/mcp", m.get("resource_documentation"));
    }

    @Test
    void build_omitsEmptyScopes_andNullDocumentation() {
        final Map<String, Object> m = ProtectedResourceMetadata.build(
                "https://mcp.example", List.of("https://as.example"), List.of(), null);

        assertFalse(m.containsKey("scopes_supported"), "empty scopes are omitted, not an empty array");
        assertFalse(m.containsKey("resource_documentation"), "null documentation is omitted");
        assertEquals("https://mcp.example", m.get("resource"));
    }
}
