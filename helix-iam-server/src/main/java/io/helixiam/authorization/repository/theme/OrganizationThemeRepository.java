/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.theme;

import io.helixiam.authorization.domain.theme.OrganizationThemeRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for organization theme layers. */
@Repository
public interface OrganizationThemeRepository extends JpaRepository<OrganizationThemeRecord, String> {

    List<OrganizationThemeRecord> findAllByRealmId(String realmId);
}
