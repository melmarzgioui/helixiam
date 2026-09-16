/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.device;

import io.helixiam.authorization.domain.device.DeviceCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for enrolled device-factor signing credentials ({@link DeviceCredentialEntity}). */
@Repository
public interface DeviceCredentialRepository extends JpaRepository<DeviceCredentialEntity, String> {

    List<DeviceCredentialEntity> findAllByUserId(String userId);
}
