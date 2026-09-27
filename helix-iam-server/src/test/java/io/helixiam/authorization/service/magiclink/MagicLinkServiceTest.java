/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.magiclink;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 1.0 item 6: magic-link tokens against the real schema — hashed, 15-minute expiry, single use, rate limits. */
@Testcontainers
class MagicLinkServiceTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");
    static JdbcTemplate jdbc;

    private final AtomicLong now = new AtomicLong(1_790_000_000_000L);
    private final List<MagicLinkMessage> sent = new ArrayList<>();
    private MagicLinkService service;

    @BeforeAll
    static void migrate() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();
        jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('mf', 'mf') ON CONFLICT DO NOTHING");
        jdbc.update("INSERT INTO user_credentials (user_id, username, email) VALUES ('u-1', 'joe', 'joe@example.com') ON CONFLICT DO NOTHING");
    }

    @BeforeEach
    void setUp() {
        final RealmConfigRepository realms = mock(RealmConfigRepository.class);
        final RealmConfig cfg = new RealmConfig();
        cfg.setMagicLinkEnabled(true);
        when(realms.findById("mf")).thenReturn(Optional.of(cfg));
        final UserCredentialsRepository users = mock(UserCredentialsRepository.class);
        final UserCredentials joe = new UserCredentials();
        joe.setUserId("u-1");
        joe.setEmail("joe@example.com");
        when(users.findByEmail("joe@example.com")).thenReturn(Optional.of(joe));
        when(users.findByEmail("nobody@example.com")).thenReturn(Optional.empty());
        final TenantUserRepository memberships = mock(TenantUserRepository.class);
        when(memberships.findByTenantIdAndUserId(anyString(), anyString())).thenReturn(Optional.empty());
        when(memberships.findByTenantIdAndUserId("mf", "u-1")).thenReturn(Optional.of(new TenantUser()));
        service = new MagicLinkService(jdbc, realms, users, memberships, sent::add, now::get);
    }

    private String requestToken(final String ip) {
        final int before = sent.size();
        service.request("mf", "Joe@Example.com ", ip, "https://idp.example/realms/mf");
        assertThat(sent).hasSize(before + 1);
        final String link = sent.get(sent.size() - 1).link();
        assertThat(link).startsWith("https://idp.example/realms/mf/login/magic/verify?token=");
        return link.substring(link.indexOf("token=") + 6);
    }

    @Test
    void storedHashed_singleUse_andBoundToItsRealm() {
        final String token = requestToken("10.0.0.1");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM magic_link_token WHERE token_hash = ?", Integer.class,
                MagicLinkService.hash(token))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM magic_link_token WHERE token_hash = ?", Integer.class, token)).isZero();

        assertThat(service.consume("other-realm", token)).isEmpty();
        assertThat(service.consume("mf", token)).contains("u-1");
        assertThat(service.consume("mf", token)).as("second use").isEmpty();
        assertThat(service.consume("mf", "not-a-token")).isEmpty();
    }

    @Test
    void expiresAfter15Minutes() {
        final String fresh = requestToken("10.0.0.2");
        final String stale = requestToken("10.0.0.2");
        now.addAndGet(TimeUnit.MINUTES.toMillis(14));
        assertThat(service.consume("mf", fresh)).contains("u-1");
        now.addAndGet(TimeUnit.MINUTES.toMillis(2));
        assertThat(service.consume("mf", stale)).isEmpty();
    }

    @Test
    void unknownAddressSendsNothing_andRequestsAreLimitedPerIp() {
        service.request("mf", "nobody@example.com", "10.0.0.3", "https://idp.example/realms/mf");
        assertThat(sent).isEmpty();
        for (int i = 0; i < 30; i++) {
            service.request("mf", "nobody@example.com", "10.0.0.9", "https://idp.example/realms/mf");
        }
        // The per-IP budget (20) is spent even by unknown addresses, so a known one from that IP is refused too.
        service.request("mf", "joe@example.com", "10.0.0.9", "https://idp.example/realms/mf");
        assertThat(sent).isEmpty();
        now.addAndGet(TimeUnit.MINUTES.toMillis(16));
        service.request("mf", "joe@example.com", "10.0.0.9", "https://idp.example/realms/mf");
        assertThat(sent).hasSize(1);
    }
}
