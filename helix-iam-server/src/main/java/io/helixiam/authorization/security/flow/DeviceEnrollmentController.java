/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.device.DeviceEnrollmentService;
import io.helixiam.authorization.flow.device.DeviceEnrollmentTicket;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Helix IAM E4.1 (deferred): mobile-facing device enrollment. The logged-in user calls
 * {@code POST /device/enroll/start} (authenticated) to mint a single-use ticket (shown to the phone
 * as a QR/deeplink); the phone calls {@code POST /device/enroll} (anonymous) with its public key +
 * platform attestation to redeem it. The enrolled user comes from the ticket, not the request.
 */
@RestController
public class DeviceEnrollmentController {

    private final DeviceEnrollmentService deviceEnrollmentService;

    public DeviceEnrollmentController(final DeviceEnrollmentService deviceEnrollmentService) {
        this.deviceEnrollmentService = deviceEnrollmentService;
    }

    /** Logged-in user: mint a single-use enrollment ticket (id + attestation nonce) for their phone. */
    @PostMapping("/device/enroll/start")
    public Map<String, String> start(@AuthenticationPrincipal final UserCredentials user) {
        final DeviceEnrollmentTicket ticket = deviceEnrollmentService.start(user.getUserId());
        return Map.of("ticketId", ticket.id(), "nonce", ticket.nonce());
    }

    /** Phone (anonymous): redeem the ticket with the device key + attestation; subscriber verifies + stores. */
    @PostMapping("/device/enroll")
    public Map<String, Boolean> enroll(@RequestBody final EnrollRequest request) {
        final boolean enrolled = deviceEnrollmentService.complete(request.ticketId(), request.deviceId(),
                request.publicKey(), request.platform(), request.attestation(), request.biometric());
        return Map.of("enrolled", enrolled);
    }

    /** Phone enrollment payload: the ticket + the device's SPKI public key + platform attestation. */
    public record EnrollRequest(String ticketId, String deviceId, String publicKey, String platform,
                                String attestation, boolean biometric) {
    }
}
