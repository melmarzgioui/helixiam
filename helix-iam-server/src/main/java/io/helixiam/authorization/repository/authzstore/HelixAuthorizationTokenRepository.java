/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.authzstore;

import io.helixiam.authorization.domain.authzstore.HelixAuthorizationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** The findByToken index for the queue-backed authorization store (Q1). */
@Repository
public interface HelixAuthorizationTokenRepository extends JpaRepository<HelixAuthorizationToken, String> {

    void deleteByAuthorizationId(String authorizationId);
}
