/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.messaging;

import io.helixiam.authorization.domain.messaging.DevicePushToken;
import io.helixiam.authorization.domain.messaging.admin.DevicePushTokenDto;
import io.helixiam.authorization.repository.messaging.DevicePushTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Helix IAM notifications (N6c): the per-realm store of users' push device tokens. The mobile app registers a
 * token after enrollment; the push-approval sender looks them up by user to deliver via FCM / APNs.
 */
@Service
public class DevicePushTokenService {

    private final DevicePushTokenRepository tokens;

    public DevicePushTokenService(final DevicePushTokenRepository tokens) {
        this.tokens = tokens;
    }

    /** Register (idempotent upsert by realm + user + platform + token) a device push token. */
    @Transactional
    public DevicePushTokenDto register(final DevicePushTokenDto dto) {
        final DevicePushToken entity = tokens
                .findByRealmIdAndUserIdAndPlatformAndToken(dto.realmId(), dto.userId(), dto.platform(), dto.token())
                .orElseGet(DevicePushToken::new);
        entity.setRealmId(dto.realmId());
        entity.setUserId(dto.userId());
        entity.setPlatform(dto.platform());
        entity.setToken(dto.token());
        final DevicePushToken saved = tokens.save(entity);
        return new DevicePushTokenDto(saved.getRealmId(), saved.getUserId(), saved.getPlatform(), saved.getToken());
    }

    /** All push tokens registered for a user in a realm. */
    public List<DevicePushTokenDto> list(final String realmId, final String userId) {
        return tokens.findByRealmIdAndUserId(realmId, userId).stream()
                .map(t -> new DevicePushTokenDto(t.getRealmId(), t.getUserId(), t.getPlatform(), t.getToken()))
                .toList();
    }
}
