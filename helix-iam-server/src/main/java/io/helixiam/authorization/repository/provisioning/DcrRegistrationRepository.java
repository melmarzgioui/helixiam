/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.provisioning;

import io.helixiam.authorization.domain.provisioning.DcrRegistration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Persistence for {@link DcrRegistration} (RFC 7592 manage credential binding). */
@Repository
public interface DcrRegistrationRepository extends JpaRepository<DcrRegistration, String> {

    Optional<DcrRegistration> findByRealmIdAndClientInternalId(String realmId, String clientInternalId);
}
