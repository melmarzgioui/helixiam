/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.realm;

import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Helix IAM SSO P3: a short-TTL cache over {@link RealmAdminPublisher#get(String)} so login-time SSO
 * session-policy enforcement (idle/max/remember-me) reads the realm config without an AMQP round-trip on
 * every request. Any lookup failure yields platform defaults so token/login flow never breaks.
 */
@Component
public class RealmSettingsResolver {

    private static final Logger LOG = LogManager.getLogger(RealmSettingsResolver.class);

    public static final int DEFAULT_IDLE_SECONDS = 1_800;
    public static final int DEFAULT_MAX_LIFETIME_SECONDS = 36_000;
    public static final int DEFAULT_REMEMBER_ME_SECONDS = 2_592_000;

    private final RealmAdminPublisher publisher;
    private final long ttlMillis;
    private final LongSupplier nowMillis;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();
    // Realm-existence cache (positive AND negative), so the realm-routing filter can 404 unknown realms
    // without an AMQP round-trip per request and a bogus-realm spray can't hammer the queue.
    private final ConcurrentHashMap<String, ExistsCached> existsCache = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public RealmSettingsResolver(final RealmAdminPublisher publisher) {
        this(publisher, 30_000L, System::currentTimeMillis);
    }

    /** Test seam: configurable TTL + clock. */
    RealmSettingsResolver(final RealmAdminPublisher publisher, final long ttlMillis, final LongSupplier nowMillis) {
        this.publisher = publisher;
        this.ttlMillis = ttlMillis;
        this.nowMillis = nowMillis;
    }

    /** The realm's settings (cached up to the TTL); platform defaults if the lookup fails. */
    public RealmSettingsDto get(final String realmId) {
        final Cached cached = cache.get(realmId);
        if (cached != null && nowMillis.getAsLong() - cached.loadedAt < ttlMillis) {
            return cached.value;
        }
        try {
            final RealmSettingsDto fresh = publisher.get(realmId);
            if (fresh != null) {
                cache.put(realmId, new Cached(fresh, nowMillis.getAsLong()));
                return fresh;
            }
        } catch (final RuntimeException e) {
            LOG.warn("Realm-settings lookup failed for {}, using SSO-policy defaults: {}", realmId, e.getMessage());
        }
        return defaults(realmId);
    }

    /**
     * Whether the realm exists (the subscriber returns settings for it). Cached (positive + negative) up to
     * the TTL. <b>Fails open</b> — a lookup error returns {@code true} so a transient AMQP hiccup never 404s
     * a valid realm. Used by the realm-routing filter to reject unknown-realm requests (Keycloak parity).
     */
    public boolean exists(final String realmId) {
        final ExistsCached cached = existsCache.get(realmId);
        if (cached != null && nowMillis.getAsLong() - cached.loadedAt < ttlMillis) {
            return cached.value;
        }
        boolean present;
        try {
            // Raw existence (a realm-config row exists) — NOT publisher.get(), which synthesizes platform
            // defaults for any id and would report every bogus realm as existing.
            final Boolean answer = publisher.exists(realmId);
            present = Boolean.TRUE.equals(answer);
        } catch (final RuntimeException e) {
            LOG.warn("Realm-existence lookup failed for {}, failing open (treated as existing): {}", realmId, e.getMessage());
            return true; // fail open: never 404 a possibly-valid realm on a lookup error
        }
        existsCache.put(realmId, new ExistsCached(present, nowMillis.getAsLong()));
        return present;
    }

    private static RealmSettingsDto defaults(final String realmId) {
        return new RealmSettingsDto(realmId, realmId, null, 3600, 5_184_000, false, false, 12, true,
                DEFAULT_IDLE_SECONDS, DEFAULT_MAX_LIFETIME_SECONDS, false, DEFAULT_REMEMBER_ME_SECONDS,
                // Auth-hardening defaults: every feature off so the default login path is unchanged.
                false, 5, 900, 900, false,
                false, false, false, false, false, 0,
                false,
                "none", null, null,
                0, true,
                // Adaptive risk-based authentication defaults: policy off → login path unchanged.
                false, 40, 70, "allow", "step_up", "deny",
                // B2: no per-realm branding by default (login page uses the built-in KubeDNA theme).
                null, null, null, null, null,
                // Registration on by default; the global master flag (user.register.enabled) still gates it.
                true);
    }

    private record Cached(RealmSettingsDto value, long loadedAt) {
    }

    private record ExistsCached(boolean value, long loadedAt) {
    }
}
