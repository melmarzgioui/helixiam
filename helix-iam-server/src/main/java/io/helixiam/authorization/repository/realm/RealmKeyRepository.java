/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.realm;

import io.helixiam.authorization.domain.realm.RealmKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for per-realm signing keys ({@link RealmKey}). */
@Repository
public interface RealmKeyRepository extends JpaRepository<RealmKey, String> {

    /** The current ACTIVE signing key for a realm (at most one expected). */
    Optional<RealmKey> findFirstByRealmIdAndStatusOrderByCreationDateDesc(String realmId, String status);

    /** All keys for a realm in any of the given statuses (e.g. ACTIVE + ROTATED for the JWKS). */
    List<RealmKey> findAllByRealmIdAndStatusIn(String realmId, List<String> statuses);

    /** Every key for a realm, newest first — the full lifecycle history for the admin Keys view. */
    List<RealmKey> findAllByRealmIdOrderByCreationDateDesc(String realmId);
}
