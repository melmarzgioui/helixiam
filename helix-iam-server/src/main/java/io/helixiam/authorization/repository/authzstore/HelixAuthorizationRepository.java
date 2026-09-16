/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.authzstore;

import io.helixiam.authorization.domain.authzstore.HelixAuthorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence for the queue-backed OAuth2 authorization store (Q1). */
@Repository
public interface HelixAuthorizationRepository extends JpaRepository<HelixAuthorization, String> {
}
