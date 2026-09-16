/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.realm;

import io.helixiam.authorization.domain.realm.RealmConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence for {@link RealmConfig} (keyed by realm id == tenant id). */
@Repository
public interface RealmConfigRepository extends JpaRepository<RealmConfig, String> {
}
