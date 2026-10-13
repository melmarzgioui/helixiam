/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the complete OIDC discovery document and the RFC 8414 authorization server metadata of a realm: every key and
 * every value, as HelixIAM 1.0 (Spring Authorization Server 1.5) served them. Order is ignored, both of the keys and
 * inside arrays: Spring Security 7 emits the same content in another order (for example
 * {@code grant_types_supported} lists token exchange before the device code), which JSON consumers do not see.
 */
class DiscoveryDocumentsE2eTest extends AbstractE2eTest {

    private static final List<String> CLIENT_AUTH = List.of("client_secret_basic", "client_secret_post",
            "client_secret_jwt", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth");
    private static final List<String> GRANTS = List.of("authorization_code", "client_credentials", "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange");
    private static final List<String> DPOP_ALGS = List.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512");

    @Test
    void theOidcDiscoveryDocument_hasExactlyTheseKeysAndValues() throws Exception {
        final String realm = E2eSeed.unique("disc");
        seed().realm(realm);
        final String base = baseUrl() + "/realms/" + realm;

        final Map<String, Object> expected = new LinkedHashMap<>(authorizationServerMetadata(base));
        expected.put("userinfo_endpoint", base + "/userinfo");
        expected.put("end_session_endpoint", base + "/connect/logout");
        expected.put("subject_types_supported", List.of("public"));
        expected.put("id_token_signing_alg_values_supported", List.of("RS256", "PS256"));
        expected.put("scopes_supported", List.of("openid"));
        expected.put("registration_endpoint", base + "/connect/register");
        expected.put("claims_supported", List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "azp",
                "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "email",
                "email_verified", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale",
                "updated_at", "phone_number", "phone_number_verified", "realm_access", "resource_access",
                "organizations"));
        expected.put("backchannel_logout_supported", true);
        expected.put("backchannel_logout_session_supported", true);

        assertThat(document("/realms/" + realm + "/.well-known/openid-configuration"))
                .isEqualTo(normalized(expected));
    }

    @Test
    void theRfc8414Metadata_hasExactlyTheseKeysAndValues() throws Exception {
        final String realm = E2eSeed.unique("disc");
        seed().realm(realm);
        final String base = baseUrl() + "/realms/" + realm;

        assertThat(document("/realms/" + realm + "/.well-known/oauth-authorization-server"))
                .isEqualTo(normalized(authorizationServerMetadata(base)));
    }

    /** What both documents share. */
    private static Map<String, Object> authorizationServerMetadata(final String base) {
        final Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", base);
        m.put("authorization_endpoint", base + "/oauth2/authorize");
        m.put("device_authorization_endpoint", base + "/oauth2/device_authorization");
        m.put("token_endpoint", base + "/oauth2/token");
        m.put("token_endpoint_auth_methods_supported", CLIENT_AUTH);
        m.put("jwks_uri", base + "/oauth2/jwks");
        m.put("response_types_supported", List.of("code"));
        m.put("grant_types_supported", GRANTS);
        m.put("revocation_endpoint", base + "/oauth2/revoke");
        m.put("revocation_endpoint_auth_methods_supported", CLIENT_AUTH);
        m.put("introspection_endpoint", base + "/oauth2/introspect");
        m.put("introspection_endpoint_auth_methods_supported", CLIENT_AUTH);
        m.put("code_challenge_methods_supported", List.of("S256"));
        m.put("tls_client_certificate_bound_access_tokens", true);
        m.put("dpop_signing_alg_values_supported", DPOP_ALGS);
        m.put("pushed_authorization_request_endpoint", base + "/oauth2/par");
        return m;
    }

    private Map<String, Object> document(final String path) {
        final E2eHttp.Response response = newBrowser().get(path);
        assertThat(response.status()).as(path).isEqualTo(200);
        return normalized(response.json());
    }

    /** Keys sorted, arrays sorted: compares content, not order. */
    private static Map<String, Object> normalized(final Object document) {
        final JsonNode node = new ObjectMapper().valueToTree(document);
        final Map<String, Object> out = new TreeMap<>();
        for (final Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
            final Map.Entry<String, JsonNode> field = it.next();
            out.put(field.getKey(), value(field.getValue()));
        }
        return out;
    }

    private static Object value(final JsonNode node) {
        if (node.isArray()) {
            final List<String> items = new ArrayList<>();
            node.forEach(item -> items.add(item.toString()));
            items.sort(null);
            return items;
        }
        return node.toString();
    }
}
