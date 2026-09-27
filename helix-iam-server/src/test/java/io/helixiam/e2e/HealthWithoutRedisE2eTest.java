/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.springframework.boot.test.context.SpringBootTest;

/**
 * C4: {@code sessionStore: queue} as the Helm chart sets it ({@code HELIX_SESSION_STORE=queue}, here a boot property
 * visible to environment post-processors) — {@code /actuator/health} is UP without Redis.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "HELIX_SESSION_STORE=queue",
        "management.endpoint.health.show-details=always",
        "database.encryption=0123456789abcdef0123456789abcdef",
        "idp.base.url=http://localhost:8080",
        "sp.base.url=http://localhost:8090",
        "spring.sql.init.mode=always",
        "spring.flyway.enabled=false"})
class HealthWithoutRedisE2eTest extends AbstractHealthWithoutRedisBoot {
}
