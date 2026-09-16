/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.mcp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM Agent Phase C (MCP auth): builds an <b>RFC 9728 OAuth 2.0 Protected Resource Metadata</b>
 * document — the JSON a protected resource (e.g. an MCP server) publishes at
 * {@code /.well-known/oauth-protected-resource} so an OAuth client can discover <i>which authorization
 * server</i> guards it and <i>which scopes</i> it needs, then obtain an audience-bound token.
 *
 * <p>This is the discovery half of MCP authorization (the MCP spec's auth is OAuth 2.1 +
 * RFC 8414 AS metadata + RFC 7591 DCR + RFC 8707 resource indicators + RFC 9728). Helix already serves
 * the AS metadata, DCR and resource-indicator ({@code aud}) pieces; this adds RFC 9728 so Helix can host
 * the protected-resource-metadata for a realm (or, with a {@code resource} override, on behalf of an MCP
 * server that delegates its metadata hosting to Helix).
 *
 * <p>Pure and Spring-free so it is unit-tested in isolation; the map is serialized to JSON by a controller.
 */
public final class ProtectedResourceMetadata {

    private ProtectedResourceMetadata() {
    }

    /**
     * @param resource              the protected resource's identifier (RFC 9728 {@code resource}); clients
     *                              use this as the {@code resource} indicator so the token {@code aud} binds to it.
     * @param authorizationServers  issuer identifiers of the authorization servers that protect it (Helix realm).
     * @param scopesSupported       scopes a client may request for this resource; omitted when empty.
     * @param resourceDocumentation optional human docs URL; omitted when {@code null}.
     */
    public static Map<String, Object> build(final String resource,
                                            final List<String> authorizationServers,
                                            final List<String> scopesSupported,
                                            final String resourceDocumentation) {
        final Map<String, Object> m = new LinkedHashMap<>();
        m.put("resource", resource);
        m.put("authorization_servers", new ArrayList<>(authorizationServers));
        if (scopesSupported != null && !scopesSupported.isEmpty()) {
            m.put("scopes_supported", new ArrayList<>(scopesSupported));
        }
        // MCP carries the access token in the Authorization request header — RFC 9728/6750 "header" method.
        m.put("bearer_methods_supported", List.of("header"));
        if (resourceDocumentation != null) {
            m.put("resource_documentation", resourceDocumentation);
        }
        return m;
    }
}
