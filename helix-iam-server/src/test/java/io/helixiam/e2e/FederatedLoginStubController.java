/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.federation.FederatedLoginCompleter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Test-only (active in the e2e context via {@code helix.e2e.federation-stub=true}): stands in for an upstream identity
 * provider's callback. It hands a user the "broker" authenticated to the real {@link FederatedLoginCompleter}, exactly
 * as {@code FederationBrokerController} does after validating an upstream assertion, so a browser test can drive the
 * post-broker half of a federated sign-in (session, flow, resumed authorization request) without an upstream IdP.
 * Realm-relative under the broker's (anonymous) path: {@code GET /realms/{realm}/broker/e2e-stub/complete?userId=}.
 */
@Controller
@ConditionalOnProperty(name = "helix.e2e.federation-stub", havingValue = "true")
public class FederatedLoginStubController {

    private final FederatedLoginCompleter completer;

    public FederatedLoginStubController(final FederatedLoginCompleter completer) {
        this.completer = completer;
    }

    @GetMapping("/broker/e2e-stub/complete")
    public String complete(@RequestParam final String userId, final HttpServletRequest request,
                           final HttpServletResponse response) {
        return completer.complete(userId, request, response);
    }
}
