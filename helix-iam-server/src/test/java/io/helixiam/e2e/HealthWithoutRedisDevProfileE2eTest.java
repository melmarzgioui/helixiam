/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.springframework.boot.test.context.SpringBootTest;

/**
 * C4: the {@code dev} profile keeps sessions in PostgreSQL by default ({@code application-dev.properties}) —
 * {@code /actuator/health} is UP without Redis.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.profiles.active=dev",
        "management.endpoint.health.show-details=always",
        "spring.sql.init.mode=always",
        "spring.flyway.enabled=false"})
class HealthWithoutRedisDevProfileE2eTest extends AbstractHealthWithoutRedisBoot {
}
