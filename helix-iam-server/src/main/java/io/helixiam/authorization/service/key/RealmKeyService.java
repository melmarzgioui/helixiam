/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import io.helixiam.authorization.domain.realm.RealmKey;
import io.helixiam.authorization.domain.realm.RealmKeyView;
import io.helixiam.authorization.repository.realm.RealmKeyRepository;
import io.helixiam.common.log.LogSafe;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.persistence.security.AttributeEncryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages per-realm signing keys with zero-downtime, staged rollover (Helix IAM E1.4; bring-your-own keys, see
 * {@code docs/superpowers/specs/2026-10-16-byo-realm-keys-design.md}).
 *
 * <p>Each realm has one ACTIVE key (signs). New keys can be <b>staged</b> as PENDING — imported with a certificate
 * chain ({@link #importKey}) or generated with a CSR ({@link #createCsr}, the private key never leaves the server) —
 * and are published (JWKS, SAML metadata) but do not sign until {@link #activate}, which demotes the previous ACTIVE
 * key to ROTATED (still published until retired). {@link #rotate} generates and activates at once. Key material comes
 * from a pluggable {@link SigningKeyProvider}. Key material is never logged.
 */
@Service
public class RealmKeyService {

    private static final Logger LOG = LogManager.getLogger(RealmKeyService.class);
    private static final String ENCRYPTION_PROBE = "helix-encryption-probe";
    private static final List<String> PUBLISHED = List.of(RealmKey.Status.ACTIVE.name(),
            RealmKey.Status.PENDING.name(), RealmKey.Status.ROTATED.name());

    private final RealmKeyRepository realmKeyRepository;
    private final SigningKeyProvider keyProvider;
    private final boolean encrypted;
    private final DeploymentProfile profile;
    private final ApplicationEventPublisher events;

    /** Tests: encryption assumed configured, no cache events. */
    public RealmKeyService(final RealmKeyRepository realmKeyRepository, final SigningKeyProvider keyProvider) {
        this(realmKeyRepository, keyProvider, true, DeploymentProfile.production(), null);
    }

    @Autowired
    public RealmKeyService(final RealmKeyRepository realmKeyRepository, final SigningKeyProvider keyProvider,
                           @Value("${database.encryption:#{null}}") final String encryptionKey,
                           final DeploymentProfile profile, final ApplicationEventPublisher events) {
        this(realmKeyRepository, keyProvider,
                !ENCRYPTION_PROBE.equals(new AttributeEncryption(encryptionKey).convertToDatabaseColumn(ENCRYPTION_PROBE)),
                profile, events);
    }

    RealmKeyService(final RealmKeyRepository realmKeyRepository, final SigningKeyProvider keyProvider,
                    final boolean encrypted, final DeploymentProfile profile, final ApplicationEventPublisher events) {
        this.realmKeyRepository = realmKeyRepository;
        this.keyProvider = keyProvider;
        this.encrypted = encrypted;
        this.profile = profile;
        this.events = events;
    }

    /** A CSR key and its PKCS#10 request (PEM). */
    public record CsrResult(RealmKey key, String csrPem) {
    }

    /** The outcome of {@link #retire}. */
    public enum RetireOutcome { RETIRED, NOT_FOUND, ACTIVE_REFUSED }

    /** A state conflict (activate a non-PENDING key, attach to a retired key …): the admin API's 409. */
    public static class KeyStateException extends RuntimeException {
        public KeyStateException(final String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------------------------------------------ reads

    /** Returns the realm's ACTIVE signing key, generating + persisting one if none exists. */
    public RealmKey getOrCreateActive(final String realmId) {
        return realmKeyRepository
                .findFirstByRealmIdAndStatusOrderByCreationDateDesc(realmId, RealmKey.Status.ACTIVE.name())
                .orElseGet(() -> generateActive(realmId, RealmKeyMaterial.RS256));
    }

    /**
     * Returns the realm's ACTIVE key, importing the supplied key material as ACTIVE if the realm has no key yet. Used
     * to seed the store from an existing (e.g. {@code /jks}) keypair so the signing key material — and therefore the
     * derived JWT {@code kid} — is unchanged at cutover (token continuity). Idempotent.
     */
    public RealmKey getOrImportActive(final String realmId, final String algorithm,
                                      final String publicKeyBase64, final String privateKeyBase64) {
        return realmKeyRepository
                .findFirstByRealmIdAndStatusOrderByCreationDateDesc(realmId, RealmKey.Status.ACTIVE.name())
                .orElseGet(() -> {
                    final RealmKey seed = new RealmKey(UUID.randomUUID().toString(), realmId,
                            RealmKeyMaterial.normalizeAlgorithm(algorithm), publicKeyBase64, privateKeyBase64);
                    seed.setActivatedDate(new Date());
                    final RealmKey imported = realmKeyRepository.save(seed);
                    LOG.debug("Imported seed ACTIVE key {} for realm {}", imported.getKeyId(), realmId);
                    return imported;
                });
    }

    /** Keys to publish for verification: ACTIVE + ROTATED. */
    public List<RealmKey> verificationKeys(final String realmId) {
        return realmKeyRepository.findAllByRealmIdAndStatusIn(
                realmId, List.of(RealmKey.Status.ACTIVE.name(), RealmKey.Status.ROTATED.name()));
    }

    /** Keys the JWKS and SAML metadata publish: ACTIVE, PENDING and ROTATED. */
    public List<RealmKey> publishedKeys(final String realmId) {
        return realmKeyRepository.findAllByRealmIdAndStatusIn(realmId, PUBLISHED);
    }

    /** Every key for a realm (all statuses), newest first, as safe public views. The private key is never included. */
    public List<RealmKeyView> listViews(final String realmId) {
        final Instant now = Instant.now();
        return realmKeyRepository.findAllByRealmIdOrderByCreationDateDesc(realmId).stream()
                .map(k -> RealmKeyView.from(k, now))
                .toList();
    }

    /** A key of this realm (a key id of another realm is empty). */
    public Optional<RealmKey> find(final String realmId, final String keyId) {
        if (keyId == null || keyId.isBlank()) {
            return Optional.empty();
        }
        return realmKeyRepository.findByKeyIdAndRealmId(keyId, realmId);
    }

    // ------------------------------------------------------------------------------------------------ writes

    /** Generates a key of {@code algorithm} and activates it at once (the previous ACTIVE key becomes ROTATED). */
    @Transactional
    public RealmKey rotate(final String realmId, final String algorithm) {
        final String alg = RealmKeyMaterial.requireSupportedAlgorithm(algorithm);
        demoteActive(realmId);
        final RealmKey key = generateActive(realmId, alg);
        changed(realmId);
        return key;
    }

    /** RS256 rotation (the pre-BYO behaviour). */
    public RealmKey rotate(final String realmId) {
        return rotate(realmId, RealmKeyMaterial.RS256);
    }

    /** Imports a PEM private key and its certificate chain (leaf first) as a PENDING key. */
    @Transactional
    public RealmKey importKey(final String realmId, final String privateKeyPem, final String certificateChainPem) {
        requireEncryption(KeyImportException.PRIVATE_KEY, realmId);
        final RealmKeyMaterial.Parsed parsed = RealmKeyMaterial.parsePrivateKey(privateKeyPem);
        final List<X509Certificate> chain = RealmKeyMaterial.parseChain(certificateChainPem);
        RealmKeyMaterial.validateChain(chain, parsed.keyPair().getPublic(), Instant.now());
        if (!RealmKeyMaterial.matches(parsed.keyPair().getPrivate(), chain.get(0).getPublicKey())) {
            throw new KeyImportException(KeyImportException.CHAIN, "The private key does not match the certificate");
        }
        final String publicB64 = b64(parsed.keyPair().getPublic().getEncoded());
        if (realmKeyRepository.existsByPublicKey(publicB64)) {
            throw new KeyImportException(KeyImportException.PRIVATE_KEY,
                    "This key is already stored (in this or another realm); every realm needs its own key");
        }
        final RealmKey key = pending(realmId, parsed.algorithm(), parsed.keyPair(), RealmKey.Source.IMPORTED);
        key.setCertificateChainPem(RealmKeyMaterial.chainToPem(chain));
        final RealmKey saved = realmKeyRepository.save(key);
        LOG.info("Imported PENDING signing key realm={} keyId={} alg={} subject={}", LogSafe.sanitize(realmId),
                saved.getKeyId(), saved.getJwsAlgorithm(),
                LogSafe.sanitize(chain.get(0).getSubjectX500Principal().getName()));
        changed(realmId);
        return saved;
    }

    /** Generates a PENDING key of {@code algorithm} and a PKCS#10 CSR for it; the private key stays on the server. */
    @Transactional
    public CsrResult createCsr(final String realmId, final String algorithm, final String subject,
                               final List<String> dnsNames) {
        final String alg = RealmKeyMaterial.requireSupportedAlgorithm(algorithm);
        RealmKeyMaterial.parseSubject(subject);
        requireEncryption(RealmKeyMaterial.ALGORITHM, realmId);
        final SigningKeyProvider.GeneratedKey generated = keyProvider.generate(alg);
        final KeyPair kp = RealmKeyMaterial.decode(alg, generated.publicKeyBase64(), generated.privateKeyBase64());
        final String csr = RealmKeyMaterial.csr(kp, alg, subject, dnsNames);
        final RealmKey key = pending(realmId, alg, kp, RealmKey.Source.CSR);
        key.setCsrPem(csr);
        final RealmKey saved = realmKeyRepository.save(key);
        LOG.info("Generated PENDING signing key with CSR realm={} keyId={} alg={}", LogSafe.sanitize(realmId),
                saved.getKeyId(), alg);
        changed(realmId);
        return new CsrResult(saved, csr);
    }

    /**
     * Attaches a certificate chain (leaf first) to a PENDING or ACTIVE key of this realm; the leaf must be for that
     * key.
     *
     * @throws NoSuchElementException no such key in this realm
     * @throws KeyStateException      the key is ROTATED or RETIRED
     */
    @Transactional
    public RealmKey attachCertificate(final String realmId, final String keyId, final String certificateChainPem) {
        final RealmKey key = find(realmId, keyId).orElseThrow(() -> new NoSuchElementException("No such key"));
        if (!key.hasStatus(RealmKey.Status.PENDING) && !key.hasStatus(RealmKey.Status.ACTIVE)) {
            throw new KeyStateException("A certificate can only be attached to a pending or active key");
        }
        final List<X509Certificate> chain = RealmKeyMaterial.parseChain(certificateChainPem);
        RealmKeyMaterial.validateChain(chain,
                RealmKeyMaterial.decodePublic(key.getJwsAlgorithm(), key.getPublicKey()), Instant.now());
        key.setCertificateChainPem(RealmKeyMaterial.chainToPem(chain));
        final RealmKey saved = realmKeyRepository.save(key);
        LOG.info("Attached certificate to signing key realm={} keyId={} subject={}", LogSafe.sanitize(realmId),
                saved.getKeyId(), LogSafe.sanitize(chain.get(0).getSubjectX500Principal().getName()));
        changed(realmId);
        return saved;
    }

    /**
     * Activates a PENDING key: it signs from now on; the realm's ACTIVE key becomes ROTATED (still published).
     *
     * @throws NoSuchElementException no such key in this realm
     * @throws KeyStateException      the key is not PENDING
     */
    @Transactional
    public RealmKey activate(final String realmId, final String keyId) {
        final RealmKey key = find(realmId, keyId).orElseThrow(() -> new NoSuchElementException("No such key"));
        if (!key.hasStatus(RealmKey.Status.PENDING)) {
            throw new KeyStateException("Only a pending key can be activated (this key is " + key.getStatus() + ")");
        }
        demoteActive(realmId);
        key.setStatus(RealmKey.Status.ACTIVE);
        key.setActivatedDate(new Date());
        final RealmKey saved = realmKeyRepository.save(key);
        LOG.info("Activated signing key realm={} keyId={} alg={}", LogSafe.sanitize(realmId), saved.getKeyId(),
                saved.getJwsAlgorithm());
        changed(realmId);
        return saved;
    }

    /** Retires a key of this realm (drops it from JWKS and metadata). The ACTIVE key is refused. */
    @Transactional
    public RetireOutcome retire(final String realmId, final String keyId) {
        final Optional<RealmKey> found = find(realmId, keyId);
        if (found.isEmpty()) {
            return RetireOutcome.NOT_FOUND;
        }
        final RealmKey key = found.get();
        if (key.isActive()) {
            return RetireOutcome.ACTIVE_REFUSED;
        }
        key.setStatus(RealmKey.Status.RETIRED);
        realmKeyRepository.save(key);
        LOG.info("Retired signing key realm={} keyId={}", LogSafe.sanitize(realmId), LogSafe.sanitize(keyId));
        changed(realmId);
        return RetireOutcome.RETIRED;
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private void demoteActive(final String realmId) {
        for (final RealmKey current : realmKeyRepository.findAllByRealmIdAndStatusIn(realmId,
                List.of(RealmKey.Status.ACTIVE.name()))) {
            current.setStatus(RealmKey.Status.ROTATED);
            current.setRotatedDate(new Date());
            realmKeyRepository.save(current);
            LOG.debug("Rotated key {} for realm {} to ROTATED",
                    LogSafe.sanitize(current.getKeyId()), LogSafe.sanitize(realmId));
        }
    }

    private RealmKey pending(final String realmId, final String alg, final KeyPair kp, final RealmKey.Source source) {
        final RealmKey key = new RealmKey(UUID.randomUUID().toString(), realmId, alg,
                b64(kp.getPublic().getEncoded()), b64(kp.getPrivate().getEncoded()));
        key.setStatus(RealmKey.Status.PENDING);
        key.setSource(source);
        return key;
    }

    private RealmKey generateActive(final String realmId, final String alg) {
        final SigningKeyProvider.GeneratedKey generated = RealmKeyMaterial.RS256.equals(alg)
                ? keyProvider.generate() : keyProvider.generate(alg);
        final RealmKey key = new RealmKey(
                generated.kid(), realmId, RealmKeyMaterial.normalizeAlgorithm(generated.algorithm()),
                generated.publicKeyBase64(), generated.privateKeyBase64());
        key.setActivatedDate(new Date());
        final RealmKey saved = realmKeyRepository.save(key);
        LOG.debug("Generated ACTIVE key {} for realm {} via {} provider",
                LogSafe.sanitize(saved.getKeyId()), LogSafe.sanitize(realmId), LogSafe.sanitize(keyProvider.type()));
        return saved;
    }

    private void requireEncryption(final String field, final String realmId) {
        if (encrypted) {
            return;
        }
        if (!profile.isDev()) {
            throw new KeyImportException(field, "Database encryption is not configured: set DB_ENCRYPTION before "
                    + "importing or generating a realm signing key");
        }
        LOG.warn("DB_ENCRYPTION is not set: storing a realm signing key for realm={} UNENCRYPTED (dev profile)",
                LogSafe.sanitize(realmId));
    }

    private void changed(final String realmId) {
        if (events != null) {
            events.publishEvent(new RealmKeysChangedEvent(realmId));
        }
    }

    private static String b64(final byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
