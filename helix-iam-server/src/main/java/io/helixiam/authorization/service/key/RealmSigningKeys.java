/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

/**
 * Per-realm signing keys with an X.509 chain, addressed by a key reference. This is the minimal signing abstraction
 * for the OpenID4VP verifier access certificate (spec §9): the software store ({@link SoftwareRealmSigningKeys}) keeps
 * the key DB-encrypted; {@code pkcs11:} / {@code kms:} references are a seam for a later HSM / KMS backend and are
 * refused today with {@link UnsupportedOperationException}.
 *
 * <p>Errors: a malformed reference or invalid import input is an {@link IllegalArgumentException} (with a message
 * fit for an admin); a reference to a key that does not exist <em>in the given realm</em> (including another realm's
 * key) is a {@link java.util.NoSuchElementException} ("not found"). An import refusal is a {@link KeyImportException}
 * (an {@code IllegalArgumentException} naming the form field it belongs to).
 */
public interface RealmSigningKeys {
    /** "software:<realm>/<name>" now; "pkcs11:" / "kms:" refs are rejected with a clear message (seam for later). */
    SigningKeyHandle resolve(String realmId, String keyRef);
    /** Admin upload of a key + chain (software store, DB-encrypted). Returns the keyRef. */
    String importKey(String realmId, String name, String privateKeyPem, String certificateChainPem);

    /**
     * The keys stored for {@code realmId}, oldest first, public parts only (the admin console's key picker). A backend
     * whose keys cannot be enumerated (an HSM / KMS seam) lists none.
     */
    default java.util.List<SigningKeySummary> list(final String realmId) {
        return java.util.List.of();
    }
}
