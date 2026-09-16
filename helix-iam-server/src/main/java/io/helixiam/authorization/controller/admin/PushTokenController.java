/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.messaging.DevicePushTokenDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM notifications (N6c): registration of users' push device tokens (FCM / APNs). A mobile app POSTs
 * its registration token here after enrollment so push approvals can be delivered. The realm is authoritative
 * from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/messaging/push-tokens")
public class PushTokenController {

    private final MessagingAdminPublisher publisher;

    public PushTokenController(final MessagingAdminPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<DevicePushTokenDto> list(@PathVariable final String realmId, @RequestParam final String userId) {
        return publisher.listPushTokens(new MessagingAdminPublisher.PushTokenQuery(realmId, userId));
    }

    @PostMapping
    public DevicePushTokenDto register(@PathVariable final String realmId, @Valid @RequestBody final RegisterRequest body) {
        return publisher.registerPushToken(new DevicePushTokenDto(realmId, body.userId(),
                body.platform() == null ? null : body.platform().toUpperCase(), body.token()));
    }

    /** Registration body: the user, platform ({@code FCM}/{@code APNS}) and device token. */
    public record RegisterRequest(@NotBlank(message = "User id is required.") String userId, String platform,
                                  @NotBlank(message = "Device token is required.") String token) {
    }
}
