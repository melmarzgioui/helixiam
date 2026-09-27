/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.security.session.AuthTimeStamper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only (active in the e2e context via {@code helix.e2e.account-clock=true}): moves the calling session's
 * {@code auth_time} into the past, so a test can reach the account console's step-up without waiting five minutes.
 * Realm-relative: {@code GET /realms/{realm}/e2e/age-auth-time?seconds=600}.
 */
@RestController
@ConditionalOnProperty(name = "helix.e2e.account-clock", havingValue = "true")
public class AccountClockTestController {

    @GetMapping("/e2e/age-auth-time")
    public String age(@RequestParam final long seconds, final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session == null || !(session.getAttribute(AuthTimeStamper.HELIX_AUTH_TIME) instanceof Long authTime)) {
            return "no auth_time";
        }
        session.setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, authTime - seconds);
        return "auth_time=" + (authTime - seconds);
    }
}
