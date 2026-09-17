/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.observability;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MetricsSummaryControllerTest {

    private MeterRegistry registry;
    private HelixMetrics metrics;
    private MetricsSummaryController controller;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new HelixMetrics(registry);
        controller = new MetricsSummaryController(registry);
    }

    private static Authentication admin(final String... realms) {
        final String[] auth = new String[realms.length];
        for (int i = 0; i < realms.length; i++) {
            auth[i] = "admin_" + realms[i];
        }
        return new UsernamePasswordAuthenticationToken("u-1", "x", AuthorityUtils.createAuthorityList(auth));
    }

    @Test
    void summarisesLoginTotalsAndSuccessRate() {
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "failure");

        final Map<String, Object> body = controller.summary("master", admin("master")).getBody();

        assertThat(body).isNotNull();
        assertThat(body.get("loginSuccess")).isEqualTo(3L);
        assertThat(body.get("loginFailure")).isEqualTo(1L);
        assertThat(body.get("loginTotal")).isEqualTo(4L);
        assertThat((Double) body.get("loginSuccessRate")).isEqualTo(0.75d);
    }

    @Test
    void successRateNull_whenNoLogins() {
        final Map<String, Object> body = controller.summary("master", admin("master")).getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("loginTotal")).isEqualTo(0L);
        assertThat(body.get("loginSuccessRate")).isNull();
    }

    @Test
    void aggregatesTokensAndAdminWritesAcrossTags() {
        metrics.recordTokenIssued("master", "authorization_code");
        metrics.recordTokenIssued("master", "client_credentials");
        metrics.recordAdminWrite("master", "POST", "success");
        metrics.recordAdminWrite("master", "DELETE", "denied");

        final Map<String, Object> body = controller.summary("master", admin("master")).getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("tokensIssued")).isEqualTo(2L);
        assertThat(body.get("adminWrites")).isEqualTo(2L);
    }

    @Test
    void realmAdmin_seesOwnRealm_butAllRealmsAggregateIsMasterOnly() {
        metrics.recordLogin("master", "success");
        metrics.recordLogin("tenant-a", "failure");

        // A tenant-a admin may read tenant-a, and the master admin may read the cross-realm aggregate.
        final Map<String, Object> ownRealm = controller.summary("tenant-a", admin("tenant-a")).getBody();
        final Map<String, Object> all = controller.summary(null, admin("master")).getBody();

        assertThat(ownRealm).isNotNull();
        assertThat(ownRealm.get("loginFailure")).isEqualTo(1L);
        assertThat(all).isNotNull();
        assertThat(all.get("loginTotal")).isEqualTo(2L);
    }

    @Test
    void crossTenant_isForbidden() {
        // Pentest P1: a realm admin must not read ANOTHER realm's figures via ?realm=, ...
        assertThat(controller.summary("tenant-a", admin("gov")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        // ...nor the cross-realm aggregate (that is master-admin only)...
        assertThat(controller.summary(null, admin("gov")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(controller.summary("", admin("gov")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        // ...and a master admin is NOT implicitly admin of a tenant realm.
        assertThat(controller.summary("gov", admin("master")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void authorizedRequest_returns200_neverThrows() {
        assertThat(controller.summary("master", admin("master")).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(controller.summary(null, admin("master")).getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
