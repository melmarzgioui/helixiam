/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.key;


import java.util.List;

/**
 * Helix IAM B8: the admin API's seam onto the per-realm signing-key store (owned by the subscriber).
 * Backs the console's "Realm keys" screen — list the realm's keys, rotate the active key
 * (zero-downtime) and retire a rotated key. Routing keys are all-dots so the subscriber's
 * dash→dot binding derivation matches (see the AMQP routing-key gotcha).
 */
public interface RealmKeyConfigPublisher {

    String EXCHANGE_AUTHORIZATION_REALM_KEYS = "exchange-authorization-realm-keys";
    String REALM_KEYS_LIST = "authorization.realm.keys.list";
    String REALM_KEYS_ROTATE = "authorization.realm.keys.rotate";
    String REALM_KEYS_RETIRE = "authorization.realm.keys.retire";

    /** All keys for a realm (ACTIVE/ROTATED/RETIRED), newest first. */
    List<RealmKeyView> list(final String realmId);

    /** Rotate the realm's active signing key; returns the freshly generated ACTIVE key. */
    RealmKeyView rotate(final String realmId);

    /** Retire a key by id; {@code false} if no such key exists. */
    Boolean retire(final String keyId);
}
