/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.springframework.boot.test.context.SpringBootTest;

/**
 * Review #11: the documented "no key" mode really starts. {@code DB_ENCRYPTION} unset reaches the app as an empty
 * {@code database.encryption}, which must mean "no key" (not an empty AES key); outside dev the operator accepts it
 * with {@code HELIX_ALLOW_PLAINTEXT_SECRETS=true}. The boot creates the realm signing keys through the converter.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "HELIX_SESSION_STORE=queue",
        "management.endpoint.health.show-details=always",
        "database.encryption=",
        "helix.allow-plaintext-secrets=true",
        "idp.base.url=http://localhost:8080",
        "sp.base.url=http://localhost:8090",
        "spring.sql.init.mode=always",
        "spring.flyway.enabled=false"})
class NoEncryptionKeyBootE2eTest extends AbstractHealthWithoutRedisBoot {
}
