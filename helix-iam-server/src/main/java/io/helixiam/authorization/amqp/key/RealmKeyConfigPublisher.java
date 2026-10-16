/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.key;


import java.util.List;
import java.util.Optional;

/**
 * Helix IAM B8: the admin API's seam onto the per-realm signing-key store. Backs the console's "Realm keys" screen —
 * list, import a key + certificate chain, generate a key + CSR, attach a CA-signed chain, activate a staged key,
 * rotate (generate + activate) and retire. Every key-id operation is scoped to the realm: a key of another realm is
 * "not found". Errors: {@code KeyImportException} (400 on a field), {@code NoSuchElementException} (404),
 * {@code RealmKeyService.KeyStateException} (409).
 */
public interface RealmKeyConfigPublisher {

    String EXCHANGE_AUTHORIZATION_REALM_KEYS = "exchange-authorization-realm-keys";
    String REALM_KEYS_LIST = "authorization.realm.keys.list";
    String REALM_KEYS_ROTATE = "authorization.realm.keys.rotate";
    String REALM_KEYS_RETIRE = "authorization.realm.keys.retire";

    /** A CSR key and its PKCS#10 request (PEM, public). */
    record CsrView(RealmKeyView key, String csrPem) {
    }

    /** Outcome of {@link #retire}: RETIRED, NOT_FOUND or ACTIVE_REFUSED. */
    enum RetireOutcome { RETIRED, NOT_FOUND, ACTIVE_REFUSED, IN_USE }

    /** All keys for a realm (every status), newest first. */
    List<RealmKeyView> list(String realmId);

    /** Generate a key of {@code algorithm} (RS256 default) and activate it at once. */
    RealmKeyView rotate(String realmId, String algorithm);

    /** Import a PEM private key + chain (leaf first) as a PENDING key. */
    RealmKeyView importKey(String realmId, String privateKeyPem, String certificateChainPem);

    /** Generate a PENDING key and a CSR for it. */
    CsrView createCsr(String realmId, String algorithm, String subject, List<String> dnsNames);

    /** The stored CSR of a key of this realm, if any. */
    Optional<String> csr(String realmId, String keyId);

    /** Attach a certificate chain to a PENDING or ACTIVE key of this realm. */
    RealmKeyView attachCertificate(String realmId, String keyId, String certificateChainPem);

    /** Activate a PENDING key of this realm ({@code force}: skip the minimum staging time). */
    RealmKeyView activate(String realmId, String keyId, boolean force);

    /** Retire a key of this realm (the ACTIVE key is refused). */
    RetireOutcome retire(String realmId, String keyId);
}
