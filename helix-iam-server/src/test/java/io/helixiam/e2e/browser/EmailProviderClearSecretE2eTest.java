/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The provider secret on {@code PUT /admin/realms/{r}/messaging/providers}: {@code secret} absent, null or blank keeps
 * the stored one, a value replaces it, and {@code "clearSecret": true} removes it without deleting the provider.
 */
class EmailProviderClearSecretE2eTest extends AbstractE2eTest {

    private static String providers(final String realm) {
        return "/admin/realms/" + realm + "/messaging/providers";
    }

    private static Map<String, Object> cloudflare(final boolean enabled) {
        final Map<String, Object> p = new LinkedHashMap<>();
        p.put("channel", "EMAIL");
        p.put("driver", "CLOUDFLARE");
        p.put("enabled", enabled);
        p.put("fromAddress", "no-reply@acme.example.com");
        p.put("config", Map.of("accountId", "acme0123456789"));
        return p;
    }

    private static boolean secretSet(final E2eAdminSession admin, final String realm) {
        for (final JsonNode p : admin.get(providers(realm)).json()) {
            if ("CLOUDFLARE".equals(p.path("driver").asText())) {
                return p.path("secretSet").asBoolean();
            }
        }
        throw new AssertionError("no CLOUDFLARE provider");
    }

    @Test
    void aSecretIsKept_replaced_orClearedExplicitly() {
        final String realm = E2eSeed.unique("acme-secret");
        seed().realm(realm, "Acme");
        final E2eAdminSession admin = adminSession();
        final Map<String, Object> withToken = cloudflare(false);
        withToken.put("secret", "cf-token-1");
        assertThat(admin.put(providers(realm), withToken).status()).isEqualTo(200);
        assertThat(secretSet(admin, realm)).isTrue();

        // Omitted (and blank) keep it.
        assertThat(admin.put(providers(realm), cloudflare(false)).status()).isEqualTo(200);
        final Map<String, Object> blank = cloudflare(false);
        blank.put("secret", "");
        assertThat(admin.put(providers(realm), blank).status()).isEqualTo(200);
        assertThat(secretSet(admin, realm)).isTrue();

        // Both a new secret and clearSecret: ambiguous, refused.
        final Map<String, Object> both = cloudflare(false);
        both.put("secret", "cf-token-2");
        both.put("clearSecret", true);
        final var conflict = admin.put(providers(realm), both);
        assertThat(conflict.status()).isEqualTo(400);
        assertThat(conflict.json().path("fieldErrors").has("clearSecret")).isTrue();
        assertThat(secretSet(admin, realm)).isTrue();

        // Clearing an enabled Cloudflare provider's token would leave it unusable: refused.
        final Map<String, Object> clearEnabled = cloudflare(true);
        clearEnabled.put("clearSecret", true);
        final var refused = admin.put(providers(realm), clearEnabled);
        assertThat(refused.status()).isEqualTo(400);
        assertThat(refused.json().path("fieldErrors").has("secret")).isTrue();

        // Cleared on the disabled provider; the provider stays.
        final Map<String, Object> clear = cloudflare(false);
        clear.put("clearSecret", true);
        final JsonNode saved = admin.put(providers(realm), clear).json();
        assertThat(saved.path("secretSet").asBoolean()).isFalse();
        assertThat(secretSet(admin, realm)).isFalse();
        // And enabling it again needs a token.
        assertThat(admin.put(providers(realm), cloudflare(true)).status()).isEqualTo(400);
    }
}
