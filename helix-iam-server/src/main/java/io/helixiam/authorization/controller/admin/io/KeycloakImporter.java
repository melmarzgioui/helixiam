/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.role.RoleDto;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM PROD-5 (Keycloak importer): pure translator from a Keycloak realm-export JSON into Helix's
 * {@link RealmExportDocument}, so the existing {@link RealmImportService} can upsert it idempotently — the
 * single highest-leverage adoption feature (migrate off Keycloak).
 *
 * <p>v1 maps the cleanly-portable slices: <b>OIDC clients</b> (with grant-type derivation from Keycloak's
 * flow flags), <b>realm roles</b>, and <b>identity providers</b>. Realm settings are left to the target
 * realm (null slice — chosen by the import path), and users are intentionally NOT mapped: Keycloak password
 * hashes (PBKDF2) are not portable to Helix's Argon2id, so users come via SCIM / LDAP sync / bulk import
 * (B10) and reset their password. SAML clients are skipped in v1 (mapped later).
 */
public final class KeycloakImporter {

    private KeycloakImporter() {
    }

    /** Translate a parsed Keycloak realm export into a Helix import document. */
    public static RealmExportDocument translate(final JsonNode realm) {
        final List<ClientDto> clients = new ArrayList<>();
        for (final JsonNode c : array(realm, "clients")) {
            if ("saml".equalsIgnoreCase(text(c, "protocol", "openid-connect"))) {
                continue; // v1: OIDC clients only
            }
            clients.add(toClient(c));
        }

        final List<RoleDto> roles = new ArrayList<>();
        for (final JsonNode r : array(realm.path("roles"), "realm")) {
            final String name = text(r, "name", null);
            if (name != null && !name.isBlank()) {
                roles.add(new RoleDto(null, null, name));
            }
        }

        final List<IdentityProviderConfig> idps = new ArrayList<>();
        for (final JsonNode p : array(realm, "identityProviders")) {
            idps.add(toIdp(p));
        }

        return new RealmExportDocument(RealmExportDocument.CURRENT_FORMAT_VERSION, null,
                nullIfEmpty(clients), null, nullIfEmpty(roles), null, nullIfEmpty(idps), null, null);
    }

    private static ClientDto toClient(final JsonNode c) {
        final boolean publicClient = bool(c, "publicClient", false);
        final List<String> grants = new ArrayList<>();
        if (bool(c, "standardFlowEnabled", true)) {
            grants.add("authorization_code");
            grants.add("refresh_token");
        }
        if (bool(c, "directAccessGrantsEnabled", false)) {
            grants.add("password");
        }
        if (bool(c, "serviceAccountsEnabled", false)) {
            grants.add("client_credentials");
        }
        final List<String> scopes = strings(c, "defaultClientScopes");
        if (!scopes.contains("openid")) {
            scopes.add(0, "openid");
        }
        final Map<String, String> attrs = stringMap(c.path("attributes"));
        return new ClientDto(
                null, null, text(c, "clientId", null), grants,
                strings(c, "redirectUris"), scopes, null, null, null,
                text(c, "name", null), text(c, "description", null),
                new ArrayList<>(), strings(c, "webOrigins"),
                publicClient, bool(c, "consentRequired", false), true,
                null, text(c, "rootUrl", null), text(c, "baseUrl", null), text(c, "adminUrl", null),
                false, null, null, null, false,
                publicClient ? null : "CLIENT_SECRET_BASIC", null,
                attrs.get("backchannel.logout.url"), attrs.get("frontchannel.logout.url"), null,
                null, null, null);
    }

    private static IdentityProviderConfig toIdp(final JsonNode p) {
        final String providerId = text(p, "providerId", "oidc");
        // Keycloak protocol families → Helix protocol: SAML stays SAML; everything else (oidc, google,
        // github, keycloak-oidc, …) is an OIDC-family broker.
        final String protocol = "saml".equalsIgnoreCase(providerId) ? "saml" : "oidc";
        return new IdentityProviderConfig(null, text(p, "alias", null), protocol,
                text(p, "displayName", text(p, "alias", null)), bool(p, "enabled", true),
                stringMap(p.path("config")));
    }

    // --- JSON helpers (null/missing-safe) ---

    private static Iterable<JsonNode> array(final JsonNode node, final String field) {
        final JsonNode a = node.path(field);
        return a.isArray() ? a : List.of();
    }

    private static String text(final JsonNode node, final String field, final String fallback) {
        final JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() ? fallback : v.asText();
    }

    private static boolean bool(final JsonNode node, final String field, final boolean fallback) {
        final JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() ? fallback : v.asBoolean(fallback);
    }

    private static List<String> strings(final JsonNode node, final String field) {
        final List<String> out = new ArrayList<>();
        for (final JsonNode v : array(node, field)) {
            if (!v.isNull() && !v.asText().isBlank()) {
                out.add(v.asText());
            }
        }
        return out;
    }

    private static Map<String, String> stringMap(final JsonNode node) {
        final Map<String, String> out = new LinkedHashMap<>();
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(e -> {
                if (!e.getValue().isNull()) {
                    out.put(e.getKey(), e.getValue().asText());
                }
            });
        }
        return out;
    }

    private static <T> List<T> nullIfEmpty(final List<T> list) {
        return list.isEmpty() ? null : list;
    }
}
