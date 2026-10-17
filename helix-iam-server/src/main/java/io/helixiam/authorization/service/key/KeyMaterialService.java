/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.realm.RealmKey;
import io.helixiam.common.security.RSAKeyReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Bridges the {@link RealmKey} store to concrete Java keys for token signing/verification
 * (Helix IAM E1.4).
 *
 * <p>The signing realm's ACTIVE key is served as a {@link KeyPair}. In a standalone deployment
 * (the default for this microservice) the signing realm self-generates and persists its own key
 * on first use, like every other realm. If a {@code /jks} keypair is mounted (filesystem or
 * classpath), it is imported instead so the key material — and the JWT {@code kid} derived from
 * it — is identical at cutover from a prior deployment (continuity). Rotation (see
 * {@link RealmKeyService#rotate}) then introduces new ACTIVE keys while ROTATED keys remain
 * available as verification keys for the overlap window.
 */
@Service
public class KeyMaterialService {

    private static final Logger LOG = LogManager.getLogger(KeyMaterialService.class);

    /** The realm whose keys sign tokens for the (single-issuer) authorization server. */
    public static final String SIGNING_REALM_ID = RealmConfig.ADMIN_REALM_ID;

    private static final String JKS_PRIVATE = "/jks/private-key.pkcs8";
    private static final String JKS_PUBLIC = "/jks/public-key.cert";

    private final RealmKeyService realmKeyService;

    private final org.springframework.beans.factory.ObjectProvider<io.helixiam.authorization.security.audit.AuditLog> audit;
    /** Duplicate-ACTIVE sets already reported (realm|keyIds), so the backstop warns once, not every refresh. */
    private final java.util.Set<String> reportedDuplicates = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Tests: no audit log. */
    public KeyMaterialService(final RealmKeyService realmKeyService) {
        this(realmKeyService, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public KeyMaterialService(final RealmKeyService realmKeyService,
                              final org.springframework.beans.factory.ObjectProvider<io.helixiam.authorization.security.audit.AuditLog> audit) {
        this.realmKeyService = realmKeyService;
        this.audit = audit;
    }

    /**
     * The ACTIVE signing keypair for {@code realm} (Helix IAM multi-tenant, MT-3). The admin realm
     * seeds from the existing {@code /jks} keypair so its token {@code kid} is unchanged at cutover
     * (continuity); every other realm gets its OWN freshly generated key — distinct material, so
     * tokens minted under {@code /realms/{realm}} are signed by, and verify against, that realm's JWKS.
     */
    public KeyPair activeKeyPair(final String realm) {
        final String realmId = (realm == null || realm.isBlank()) ? SIGNING_REALM_ID : realm;
        final RealmKey active;
        if (SIGNING_REALM_ID.equals(realmId) && RSAKeyReader.exists(JKS_PUBLIC) && RSAKeyReader.exists(JKS_PRIVATE)) {
            // Cutover continuity (e.g. migrating an existing deployment): import the mounted /jks
            // keypair so the signing realm's key material — and the JWT kid derived from it — is
            // unchanged. The read is guarded by exists() so the arguments are only evaluated when
            // the material is actually present.
            active = realmKeyService.getOrImportActive(SIGNING_REALM_ID, "RSA",
                    Base64.getEncoder().encodeToString(RSAKeyReader.getPublicKey(JKS_PUBLIC).getEncoded()),
                    Base64.getEncoder().encodeToString(RSAKeyReader.getPrivateKey(JKS_PRIVATE).getEncoded()));
        } else {
            // Standalone (the default for this microservice): no /jks mount, so the signing realm
            // self-generates and persists its own key on first use — exactly like every other realm.
            active = realmKeyService.getOrCreateActive(realmId);
        }
        return RealmKeyMaterial.decode(active.getJwsAlgorithm(), active.getPublicKey(), active.getPrivateKey());
    }

    /** Public keys of {@code realm}'s ROTATED RSA keys (legacy seam; {@link #publishedKeys} covers every key). */
    public List<RSAPublicKey> rotatedPublicKeys(final String realm) {
        final String realmId = (realm == null || realm.isBlank()) ? SIGNING_REALM_ID : realm;
        final List<RSAPublicKey> keys = new ArrayList<>();
        for (final RealmKey key : realmKeyService.verificationKeys(realmId)) {
            if (RealmKey.Status.ROTATED.name().equals(key.getStatus())
                    && RealmKeyMaterial.RS256.equals(key.getJwsAlgorithm())) {
                keys.add((RSAPublicKey) RealmKeyMaterial.decodePublic(key.getJwsAlgorithm(), key.getPublicKey()));
            }
        }
        return keys;
    }

    /**
     * Every key {@code realm} publishes — ACTIVE first, then PENDING, then ROTATED (newest first within a status) — with
     * its certificate chain. Ensures the realm has an ACTIVE key first (seeding the signing realm from {@code /jks}).
     * A row that can no longer be read is skipped with a warning (key id only).
     */
    public List<PublishedKey> publishedKeys(final String realm) {
        final String realmId = (realm == null || realm.isBlank()) ? SIGNING_REALM_ID : realm;
        activeKeyPair(realmId);
        final List<RealmKey> rows = new ArrayList<>(realmKeyService.publishedKeys(realmId));
        rows.sort(java.util.Comparator.comparingInt((RealmKey k) -> statusOrder(k.getStatus()))
                .thenComparing(RealmKeyService::activatedOrCreated, java.util.Comparator.reverseOrder()));
        // Backstop: at most one ACTIVE key per family may sign. The transitions are serialised per realm, so this
        // should never happen; if it does (manual SQL, a bug), keep the newest by activation, publish the others as
        // verification-only, and say so loudly — never fail signing.
        final java.util.Set<String> activeFamilies = new java.util.HashSet<>();
        final List<String> demoted = new ArrayList<>();
        final List<PublishedKey> out = new ArrayList<>();
        for (final RealmKey row : rows) {
            String status = row.getStatus();
            if (RealmKey.Status.ACTIVE.name().equals(status)
                    && !activeFamilies.add(RealmKeyMaterial.ES256.equals(row.getJwsAlgorithm()) ? "EC" : "RSA")) {
                status = RealmKey.Status.ROTATED.name();
                demoted.add(row.getKeyId());
            }
            try {
                final KeyPair kp = RealmKeyMaterial.decode(row.getJwsAlgorithm(), row.getPublicKey(), row.getPrivateKey());
                final List<java.security.cert.X509Certificate> chain = row.getCertificateChainPem() == null
                        || row.getCertificateChainPem().isBlank() ? List.of()
                        : RealmKeyMaterial.parseChain(row.getCertificateChainPem());
                out.add(new PublishedKey(row.getKeyId(), status, row.getJwsAlgorithm(), kp.getPublic(),
                        kp.getPrivate(), chain));
            } catch (final RuntimeException e) {
                LOG.warn("Skipping unreadable signing key realm={} keyId={}", io.helixiam.common.log.LogSafe.sanitize(realmId),
                        io.helixiam.common.log.LogSafe.sanitize(row.getKeyId()));
            }
        }
        if (!demoted.isEmpty()) {
            reportDuplicates(realmId, demoted);
        }
        return out;
    }

    private void reportDuplicates(final String realmId, final List<String> demoted) {
        if (!reportedDuplicates.add(realmId + "|" + String.join(",", demoted))) {
            return;
        }
        LOG.error("Realm {} has more than one ACTIVE signing key of a family; signing with the newest, publishing {} "
                + "as verification-only. Retire or re-activate keys to resolve.",
                io.helixiam.common.log.LogSafe.sanitize(realmId), demoted);
        final io.helixiam.authorization.security.audit.AuditLog log = audit == null ? null : audit.getIfAvailable();
        if (log != null) {
            log.emit(io.helixiam.authorization.security.audit.AuditEvent.admin(
                    io.helixiam.authorization.security.audit.AuditContext.nowIso(), "REALM_KEY_DUPLICATE_ACTIVE",
                    realmId, "system", null, "realm-key", demoted.get(0), "FAILURE",
                    java.util.Map.of("demotedKeyIds", String.join(",", demoted))));
        }
    }

    /**
     * The JWS algorithms the realm's ACTIVE keys can sign: an RSA key gives RS256 and PS256, an EC P-256 key ES256.
     * RS256 is always present (every realm has an ACTIVE RSA key; OIDC requires RS256).
     */
    public java.util.Set<String> activeAlgorithms(final String realm) {
        final java.util.Set<String> algs = new java.util.LinkedHashSet<>();
        for (final PublishedKey k : publishedKeys(realm)) {
            if (k.active()) {
                if (RealmKeyMaterial.ES256.equals(k.algorithm())) {
                    algs.add(RealmKeyMaterial.ES256);
                } else {
                    algs.add(RealmKeyMaterial.RS256);
                    algs.add("PS256");
                }
            }
        }
        return algs;
    }

    private static int statusOrder(final String status) {
        return switch (status) {
            case "ACTIVE" -> 0;
            case "PENDING" -> 1;
            default -> 2;
        };
    }
}
