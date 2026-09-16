/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.wysiwys.SignedTransaction;
import io.helixiam.authorization.flow.wysiwys.TransactionSigningService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Helix IAM E4.4: WYSIWYS transaction-signing endpoints (PSD2-SCA step-up). The acting (authenticated)
 * user starts a signing request for a high-risk action; the enrolled phone signs the canonical
 * challenge; the initiator polls + consumes the result once. Poll-based (not SSE), stateless against
 * the shared store. Only the phone's sign sub-path is anonymous (secured by the device signature
 * over the canonical bytes); create/status/consume require the initiator's session.
 */
@RestController
public class TransactionSigningController {

    private final TransactionSigningService transactionSigningService;

    public TransactionSigningController(final TransactionSigningService transactionSigningService) {
        this.transactionSigningService = transactionSigningService;
    }

    /** Initiator (authenticated): create a signing request; returns the id + canonical challenge to relay. */
    @PostMapping("/tx")
    public Map<String, String> create(@AuthenticationPrincipal final UserCredentials user,
                                      @RequestBody final CreateRequest request) {
        final SignedTransaction tx = transactionSigningService.create(user.getUserId(), request.action(), request.params());
        return Map.of("id", tx.id(), "challenge", tx.canonicalChallenge());
    }

    /** Initiator poll: current signing status. */
    @GetMapping("/tx/{id}")
    public Map<String, String> status(@PathVariable final String id) {
        return Map.of("status", transactionSigningService.status(id));
    }

    /** Phone: submit the device's ES256 signature over the canonical challenge. */
    @PostMapping("/tx/{id}/sign")
    public Map<String, Boolean> sign(@PathVariable final String id, @RequestBody final SignRequest request) {
        return Map.of("signed", transactionSigningService.sign(id, request.deviceId(), request.signature()));
    }

    /** Initiator (authenticated): single-use claim of the signed authorization, bound to the acting user. */
    @PostMapping("/tx/{id}/consume")
    public Map<String, Boolean> consume(@AuthenticationPrincipal final UserCredentials user,
                                        @PathVariable final String id) {
        final String authorizedUser = transactionSigningService.consume(id);
        return Map.of("authorized", authorizedUser != null && authorizedUser.equals(user.getUserId()));
    }

    /** Create payload: the action + the transaction fields shown to the user (WYSIWYS). */
    public record CreateRequest(String action, Map<String, String> params) {
    }

    /** Phone sign payload: the enrolled device + its ES256 signature over the canonical challenge. */
    public record SignRequest(String deviceId, String signature) {
    }
}
