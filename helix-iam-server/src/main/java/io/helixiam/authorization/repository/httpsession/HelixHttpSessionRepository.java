/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.httpsession;

import io.helixiam.authorization.domain.httpsession.HelixHttpSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for the queue-backed HTTP session store (Q3). */
@Repository
public interface HelixHttpSessionRepository extends JpaRepository<HelixHttpSession, String> {

    List<HelixHttpSession> findByPrincipalName(String principalName);

    void deleteByPrincipalName(String principalName);
}
