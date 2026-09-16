/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.provisioning;

import io.helixiam.authorization.domain.provisioning.RealmProvisioningConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence for {@link RealmProvisioningConfig} (keyed by realm id). */
@Repository
public interface RealmProvisioningConfigRepository extends JpaRepository<RealmProvisioningConfig, String> {
}
