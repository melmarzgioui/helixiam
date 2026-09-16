/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import io.helixiam.authorization.domain.realm.RealmKey;
import io.helixiam.authorization.repository.realm.RealmKeyRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

/**
 * Manages per-realm JWT signing keys with zero-downtime rotation (Helix IAM E1.4).
 *
 * <p>Each realm has exactly one ACTIVE key (used to sign new tokens). {@link #rotate} demotes
 * the current ACTIVE key to ROTATED (kept in the published JWKS so already-issued tokens still
 * verify) and promotes a freshly generated key to ACTIVE. {@link #verificationKeys} returns
 * ACTIVE + ROTATED keys — exactly the set the JWKS endpoint should publish. Key material comes
 * from a pluggable {@link SigningKeyProvider} (software by default; HSM/KMS-ready).
 */
@Service
public class RealmKeyService {

    private static final Logger LOG = LogManager.getLogger(RealmKeyService.class);

    private final RealmKeyRepository realmKeyRepository;
    private final SigningKeyProvider keyProvider;

    @Autowired
    public RealmKeyService(final RealmKeyRepository realmKeyRepository, final SigningKeyProvider keyProvider) {
        this.realmKeyRepository = realmKeyRepository;
        this.keyProvider = keyProvider;
    }

    /** Returns the realm's ACTIVE signing key, generating + persisting one if none exists. */
    public RealmKey getOrCreateActive(final String realmId) {
        return realmKeyRepository
                .findFirstByRealmIdAndStatusOrderByCreationDateDesc(realmId, RealmKey.Status.ACTIVE.name())
                .orElseGet(() -> generateActive(realmId));
    }

    /**
     * Returns the realm's ACTIVE key, importing the supplied key material as ACTIVE if the
     * realm has no key yet. Used to seed the store from an existing (e.g. {@code /jks})
     * keypair so the signing key material — and therefore the derived JWT {@code kid} — is
     * unchanged at cutover (token continuity). Idempotent.
     */
    public RealmKey getOrImportActive(final String realmId, final String algorithm,
                                      final String publicKeyBase64, final String privateKeyBase64) {
        return realmKeyRepository
                .findFirstByRealmIdAndStatusOrderByCreationDateDesc(realmId, RealmKey.Status.ACTIVE.name())
                .orElseGet(() -> {
                    final RealmKey imported = realmKeyRepository.save(
                            new RealmKey(java.util.UUID.randomUUID().toString(), realmId, algorithm,
                                    publicKeyBase64, privateKeyBase64));
                    LOG.debug("Imported seed ACTIVE key {} for realm {}", imported.getKeyId(), realmId);
                    return imported;
                });
    }

    /**
     * Rotates the realm's signing key: the current ACTIVE key becomes ROTATED (still
     * published for verification), and a new ACTIVE key is generated. Returns the new key.
     */
    public RealmKey rotate(final String realmId) {
        realmKeyRepository
                .findFirstByRealmIdAndStatusOrderByCreationDateDesc(realmId, RealmKey.Status.ACTIVE.name())
                .ifPresent(current -> {
                    current.setStatus(RealmKey.Status.ROTATED);
                    current.setRotatedDate(new Date());
                    realmKeyRepository.save(current);
                    LOG.debug("Rotated key {} for realm {} to ROTATED", current.getKeyId(), realmId);
                });
        return generateActive(realmId);
    }

    /** Keys to publish in the realm's JWKS: ACTIVE (signing) + ROTATED (verification overlap). */
    public List<RealmKey> verificationKeys(final String realmId) {
        return realmKeyRepository.findAllByRealmIdAndStatusIn(
                realmId, List.of(RealmKey.Status.ACTIVE.name(), RealmKey.Status.ROTATED.name()));
    }

    /**
     * Helix IAM B8: every key for a realm (ACTIVE/ROTATED/RETIRED), newest first, as safe public
     * {@link RealmKeyView}s for the admin Keys console. The private key is never included.
     */
    public List<io.helixiam.authorization.domain.realm.RealmKeyView> listViews(final String realmId) {
        return realmKeyRepository.findAllByRealmIdOrderByCreationDateDesc(realmId).stream()
                .map(io.helixiam.authorization.domain.realm.RealmKeyView::from)
                .toList();
    }

    /**
     * Permanently removes a ROTATED key from the JWKS once the overlap window has passed.
     * @return {@code true} if a key was found and retired, {@code false} if no such key id exists.
     */
    public boolean retire(final String keyId) {
        return realmKeyRepository.findById(keyId).map(key -> {
            key.setStatus(RealmKey.Status.RETIRED);
            realmKeyRepository.save(key);
            LOG.debug("Retired key {}", keyId);
            return true;
        }).orElse(false);
    }

    private RealmKey generateActive(final String realmId) {
        final SigningKeyProvider.GeneratedKey generated = keyProvider.generate();
        final RealmKey key = new RealmKey(
                generated.kid(), realmId, generated.algorithm(),
                generated.publicKeyBase64(), generated.privateKeyBase64());
        final RealmKey saved = realmKeyRepository.save(key);
        LOG.debug("Generated ACTIVE key {} for realm {} via {} provider", saved.getKeyId(), realmId, keyProvider.type());
        return saved;
    }
}
