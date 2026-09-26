/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only (active in the e2e context via {@code helix.e2e.forced-errors=true}): endpoints that fail with an
 * unhandled exception, so {@link ErrorSurfacingE2eTest} can check a real server error surfaces as a 500.
 */
@RestController
@ConditionalOnProperty(name = "helix.e2e.forced-errors", havingValue = "true")
public class ForcedErrorTestController {

    @GetMapping("/admin/realms/{realmId}/e2e-forced-error")
    public String admin(@PathVariable final String realmId) {
        throw new IllegalStateException("forced admin failure (secret-detail-must-not-leak)");
    }

    @GetMapping("/account/e2e-forced-error")
    public String account() {
        throw new IllegalStateException("forced account failure (secret-detail-must-not-leak)");
    }
}
