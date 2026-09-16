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

    @Test
    void summarisesLoginTotalsAndSuccessRate() {
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "failure");

        final Map<String, Object> body = controller.summary("master").getBody();

        assertThat(body).isNotNull();
        assertThat(body.get("loginSuccess")).isEqualTo(3L);
        assertThat(body.get("loginFailure")).isEqualTo(1L);
        assertThat(body.get("loginTotal")).isEqualTo(4L);
        assertThat((Double) body.get("loginSuccessRate")).isEqualTo(0.75d);
    }

    @Test
    void successRateNull_whenNoLogins() {
        final Map<String, Object> body = controller.summary("master").getBody();
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

        final Map<String, Object> body = controller.summary("master").getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("tokensIssued")).isEqualTo(2L);
        assertThat(body.get("adminWrites")).isEqualTo(2L);
    }

    @Test
    void realmFilter_scopesFigures() {
        metrics.recordLogin("master", "success");
        metrics.recordLogin("tenant-a", "failure");

        final Map<String, Object> master = controller.summary("master").getBody();
        final Map<String, Object> all = controller.summary(null).getBody();

        assertThat(master).isNotNull();
        assertThat(master.get("loginSuccess")).isEqualTo(1L);
        assertThat(master.get("loginFailure")).isEqualTo(0L);
        assertThat(all).isNotNull();
        assertThat(all.get("loginTotal")).isEqualTo(2L);
    }

    @Test
    void alwaysReturns200_neverThrows() {
        assertThat(controller.summary("master").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(controller.summary(null).getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
