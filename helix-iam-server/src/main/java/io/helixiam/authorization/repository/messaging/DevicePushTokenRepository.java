/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.messaging;

import io.helixiam.authorization.domain.messaging.DevicePushToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for {@link DevicePushToken} (per-realm, per-user push device tokens). */
@Repository
public interface DevicePushTokenRepository extends JpaRepository<DevicePushToken, String> {

    List<DevicePushToken> findByRealmIdAndUserId(String realmId, String userId);

    Optional<DevicePushToken> findByRealmIdAndUserIdAndPlatformAndToken(String realmId, String userId,
                                                                        String platform, String token);
}
