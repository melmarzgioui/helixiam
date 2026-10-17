/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A realm's signing-algorithm choices (table {@code realm_signing_settings}; no row = RS256 everywhere).
 *
 * <ul>
 *   <li>{@code defaultAlg} (RS256, PS256 or ES256): access tokens, logout tokens, delegation and workload-identity
 *       tokens, JARM. ID tokens follow each client's {@code id_token_signed_response_alg} (default RS256).</li>
 *   <li>{@code samlAlg} (RS256 or ES256): which ACTIVE key signs SAML.</li>
 * </ul>
 * Choosing ES256 needs an ACTIVE EC key. Cached per realm for 30 s, dropped at once on this replica when changed.
 */
@Service
public class RealmSigningSettingsService {

    private static final Logger LOG = LogManager.getLogger(RealmSigningSettingsService.class);
    private static final long TTL_MS = 30_000L;
    public static final Set<String> DEFAULT_ALGS = Set.of("RS256", "PS256", "ES256");
    public static final Set<String> SAML_ALGS = Set.of("RS256", "ES256");

    /** The settings; both never null. */
    public record Settings(String defaultAlg, String samlAlg) {
        public static final Settings DEFAULTS = new Settings("RS256", "RS256");
    }

    private record Cached(Settings settings, long at) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final KeyMaterialService keys;
    private final ApplicationEventPublisher events;
    private final RealmKeyLock lock;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    public RealmSigningSettingsService(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                                       final KeyMaterialService keys, final ApplicationEventPublisher events,
                                       final RealmKeyLock lock) {
        this.lock = lock;
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactions);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.keys = keys;
        this.events = events;
    }

    /** The realm's settings straight from the database (no cache) — for decisions taken under the realm key lock. */
    public Settings getUncached(final String realmId) {
        final List<Settings> rows = jdbc.query("SELECT default_alg, saml_alg FROM realm_signing_settings "
                + "WHERE realm_id = ?", (rs, i) -> new Settings(rs.getString(1), rs.getString(2)), realmId);
        return rows.isEmpty() ? Settings.DEFAULTS : rows.get(0);
    }

    /** The realm's settings (defaults when it has none). */
    public Settings get(final String realmId) {
        final long now = System.currentTimeMillis();
        final Cached c = cache.get(realmId);
        if (c != null && now - c.at() <= TTL_MS) {
            return c.settings();
        }
        Settings s;
        try {
            final List<Settings> rows = jdbc.query("SELECT default_alg, saml_alg FROM realm_signing_settings "
                    + "WHERE realm_id = ?", (rs, i) -> new Settings(rs.getString(1), rs.getString(2)), realmId);
            s = rows.isEmpty() ? Settings.DEFAULTS : rows.get(0);
        } catch (final RuntimeException e) {
            LOG.warn("Could not read signing settings for realm {}: {}", LogSafe.sanitize(realmId),
                    e.getClass().getSimpleName());
            s = c != null ? c.settings() : Settings.DEFAULTS;
        }
        cache.put(realmId, new Cached(s, now));
        return s;
    }

    /**
     * Validates and stores the realm's settings.
     *
     * @return field errors ({@code defaultAlg}, {@code samlAlg}); empty when saved
     */
    public Map<String, String> put(final String realmId, final String defaultAlg, final String samlAlg) {
        final String d = defaultAlg == null || defaultAlg.isBlank() ? "RS256" : defaultAlg.trim().toUpperCase();
        final String sa = samlAlg == null || samlAlg.isBlank() ? "RS256" : samlAlg.trim().toUpperCase();
        // Check and write under the realm key lock, so a concurrent retire of the EC key cannot slip in between.
        final Map<String, String> errors = tx.execute(t -> {
            lock.lock(realmId);
            final Map<String, String> e = new LinkedHashMap<>();
            final Set<String> active = keys.activeAlgorithms(realmId);
            if (!DEFAULT_ALGS.contains(d)) {
                e.put("defaultAlg", "The default signing algorithm must be RS256, PS256 or ES256");
            } else if (!active.contains(d)) {
                e.put("defaultAlg", "The realm has no active " + d + " key; activate an EC key first");
            }
            if (!SAML_ALGS.contains(sa)) {
                e.put("samlAlg", "The SAML signing algorithm must be RS256 or ES256");
            } else if (!active.contains(sa)) {
                e.put("samlAlg", "The realm has no active " + sa + " key; activate an EC key first");
            }
            if (e.isEmpty() && jdbc.update("UPDATE realm_signing_settings SET default_alg = ?, saml_alg = ?, "
                    + "updated_at = CURRENT_TIMESTAMP WHERE realm_id = ?", d, sa, realmId) == 0) {
                jdbc.update("INSERT INTO realm_signing_settings (realm_id, default_alg, saml_alg) VALUES (?, ?, ?) "
                        + "ON CONFLICT (realm_id) DO UPDATE SET default_alg = EXCLUDED.default_alg, "
                        + "saml_alg = EXCLUDED.saml_alg, updated_at = CURRENT_TIMESTAMP", realmId, d, sa);
            }
            return e;
        });
        if (errors != null && !errors.isEmpty()) {
            return errors;
        }
        cache.remove(realmId);
        events.publishEvent(new RealmKeysChangedEvent(realmId));
        LOG.info("Signing settings of realm {} set: defaultAlg={} samlAlg={}", LogSafe.sanitize(realmId), d, sa);
        return Map.of();
    }

    @EventListener
    public void onKeysChanged(final RealmKeysChangedEvent event) {
        if (event.realmId() != null) {
            cache.remove(event.realmId());
        }
    }
}
