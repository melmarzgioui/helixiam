/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.service.messaging.MessagingAdminService;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * At most one enabled email provider per realm: saving an enabled one switches the realm to it (the others are
 * disabled in the same transaction), so delivery never has to choose. Data saved before this rule is repaired at
 * startup: the most recently saved enabled provider stays enabled, and the others are disabled and logged.
 */
class EmailProviderSingleActiveE2eTest extends AbstractE2eTest {

    private static String providers(final String realm) {
        return "/admin/realms/" + realm + "/messaging/providers";
    }

    private static Map<String, Object> provider(final String driver, final boolean enabled, final Map<String, String> config) {
        final Map<String, Object> p = new LinkedHashMap<>();
        p.put("channel", "EMAIL");
        p.put("driver", driver);
        p.put("enabled", enabled);
        p.put("fromAddress", "no-reply@acme.example.com");
        p.put("config", config);
        return p;
    }

    private static Map<String, Boolean> enabledByDriver(final JsonNode list) {
        final Map<String, Boolean> out = new LinkedHashMap<>();
        list.forEach(p -> {
            if ("EMAIL".equals(p.path("channel").asText())) {
                out.put(p.path("driver").asText(), p.path("enabled").asBoolean());
            }
        });
        return out;
    }

    @Test
    void enablingAnEmailProvider_switchesTheRealmToIt() {
        final String realm = E2eSeed.unique("acme-single");
        seed().realm(realm, "Acme");
        final E2eAdminSession admin = adminSession();

        assertThat(admin.put(providers(realm), provider("LOG", true, Map.of())).status()).isEqualTo(200);
        final Map<String, Object> http = provider("HTTP", true, Map.of("url", "https://relay.example.com/send"));
        assertThat(admin.put(providers(realm), http).json().path("enabled").asBoolean()).isTrue();

        assertThat(enabledByDriver(admin.get(providers(realm)).json())).containsEntry("HTTP", true)
                .containsEntry("LOG", false);
        // Saving a disabled one changes nothing else.
        assertThat(admin.put(providers(realm), provider("LOG", false, Map.of())).status()).isEqualTo(200);
        assertThat(enabledByDriver(admin.get(providers(realm)).json())).containsEntry("HTTP", true)
                .containsEntry("LOG", false);
        // Switching back.
        assertThat(admin.put(providers(realm), provider("LOG", true, Map.of())).status()).isEqualTo(200);
        assertThat(enabledByDriver(admin.get(providers(realm)).json())).containsEntry("HTTP", false)
                .containsEntry("LOG", true);
    }

    @Test
    void severalEnabledEmailProvidersFromBefore_keepTheMostRecentlySaved_andTheOthersAreDisabledAndLogged() {
        final String realm = E2eSeed.unique("acme-legacy");
        seed().realm(realm, "Acme");
        final JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        final Instant now = Instant.now();
        new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(s -> {
            insert(jdbc, realm, "SMTP", now.minusSeconds(300));
            insert(jdbc, realm, "HTTP", now.minusSeconds(10));
            insert(jdbc, realm, "LOG", now.minusSeconds(100));
        });

        try (LogCapture log = LogCapture.of(MessagingAdminService.class)) {
            context.getBean(MessagingAdminService.class).enforceSingleEnabledEmailProvider();
            assertThat(log.text()).contains(realm).contains("HTTP").contains("SMTP").contains("LOG");
        }

        assertThat(enabledByDriver(adminSession().get(providers(realm)).json())).containsEntry("HTTP", true)
                .containsEntry("SMTP", false).containsEntry("LOG", false);
    }

    private static void insert(final JdbcTemplate jdbc, final String realm, final String driver, final Instant saved) {
        jdbc.update("INSERT INTO messaging_provider (id, realm_id, channel, driver, enabled, from_address, config, "
                        + "creation_date, modify_date) VALUES (?, ?, 'EMAIL', ?, true, 'no-reply@acme.example.com', '{}', ?, ?)",
                UUID.randomUUID().toString(), realm, driver, Timestamp.from(saved), Timestamp.from(saved));
    }
}
