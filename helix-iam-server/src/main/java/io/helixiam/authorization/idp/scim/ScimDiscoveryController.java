/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.scim;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM E7 (SCIM 2.0): the SCIM service-discovery endpoints (RFC 7644 §4) — {@code
 * /ServiceProviderConfig}, {@code /ResourceTypes} and {@code /Schemas}. These are public per the spec
 * (a client reads them to learn the SP's capabilities before authenticating) and describe Helix's
 * supported feature set: no filter-complex/sort/etag, PATCH supported, bearer (oauthbearertoken) auth.
 */
@RestController
public class ScimDiscoveryController {

    private static final String SCIM_JSON = "application/scim+json";

    @GetMapping(value = "/scim/v2/ServiceProviderConfig", produces = SCIM_JSON)
    public ResponseEntity<Map<String, Object>> serviceProviderConfig() {
        final String base = ScimSupport.baseUrl();
        final Map<String, Object> config = Map.ofEntries(
                Map.entry("schemas", List.of(ScimSchemas.SERVICE_PROVIDER_CONFIG)),
                Map.entry("documentationUri", base),
                Map.entry("patch", Map.of("supported", true)),
                Map.entry("bulk", Map.of("supported", false, "maxOperations", 0, "maxPayloadSize", 0)),
                Map.entry("filter", Map.of("supported", true, "maxResults", 200)),
                Map.entry("changePassword", Map.of("supported", false)),
                Map.entry("sort", Map.of("supported", false)),
                Map.entry("etag", Map.of("supported", false)),
                Map.entry("authenticationSchemes", List.of(Map.of(
                        "type", "oauthbearertoken",
                        "name", "OAuth Bearer Token",
                        "description", "Authentication via a per-realm SCIM bearer token.",
                        "primary", true))),
                Map.entry("meta", Map.of("resourceType", "ServiceProviderConfig",
                        "location", base + "/ServiceProviderConfig")));
        return scim(config);
    }

    @GetMapping(value = "/scim/v2/ResourceTypes", produces = SCIM_JSON)
    public ResponseEntity<ScimListResponse<Map<String, Object>>> resourceTypes() {
        final String base = ScimSupport.baseUrl();
        final List<Map<String, Object>> types = List.of(
                resourceType(base, "User", "User", "/Users", ScimSchemas.USER),
                resourceType(base, "Group", "Group", "/Groups", ScimSchemas.GROUP));
        return scim(ScimListResponse.of(types, types.size(), 1));
    }

    @GetMapping(value = "/scim/v2/Schemas", produces = SCIM_JSON)
    public ResponseEntity<ScimListResponse<Map<String, Object>>> schemas() {
        final List<Map<String, Object>> schemas = List.of(
                Map.of("id", ScimSchemas.USER, "name", "User",
                        "description", "SCIM core User schema (RFC 7643 §4.1)."),
                Map.of("id", ScimSchemas.GROUP, "name", "Group",
                        "description", "SCIM core Group schema (RFC 7643 §4.2)."));
        return scim(ScimListResponse.of(schemas, schemas.size(), 1));
    }

    private static Map<String, Object> resourceType(final String base, final String id, final String name,
                                                     final String endpoint, final String schema) {
        return Map.ofEntries(
                Map.entry("schemas", List.of(ScimSchemas.RESOURCE_TYPE)),
                Map.entry("id", id),
                Map.entry("name", name),
                Map.entry("endpoint", endpoint),
                Map.entry("schema", schema),
                Map.entry("meta", Map.of("resourceType", "ResourceType", "location",
                        base + "/ResourceTypes/" + id)));
    }

    private static <T> ResponseEntity<T> scim(final T body) {
        return ResponseEntity.ok().header("Content-Type", SCIM_JSON).body(body);
    }
}
