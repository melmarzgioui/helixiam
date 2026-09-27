/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.theme;

import io.helixiam.authorization.domain.theme.RealmThemeRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence for realm theme layers. */
@Repository
public interface RealmThemeRepository extends JpaRepository<RealmThemeRecord, String> {
}
