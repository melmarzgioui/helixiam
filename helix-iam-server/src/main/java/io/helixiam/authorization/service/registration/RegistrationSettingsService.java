/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.registration;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Item A8: the realm's {@code postRegistrationRedirectUrl}, the page a user goes to after registering or verifying
 * their email when no sign-in is pending. It must be an absolute http(s) URL whose origin is the origin of a redirect
 * URI registered for a client of the realm, so the IdP never becomes an open redirect: checked when it is saved and
 * again when it is used (a client may have been removed since).
 */
@Service
public class RegistrationSettingsService {

    public static final int MAX_LENGTH = 2048;
    private static final Logger LOG = LogManager.getLogger(RegistrationSettingsService.class);

    private final RealmConfigRepository realms;
    private final ServiceProviderRepository clients;

    public RegistrationSettingsService(final RealmConfigRepository realms, final ServiceProviderRepository clients) {
        this.realms = realms;
        this.clients = clients;
    }

    /** The realm's settings; empty when the realm does not exist. */
    @Transactional(readOnly = true)
    public Optional<Settings> get(final String realmId) {
        return realm(realmId).map(cfg -> new Settings(cfg.getPostRegistrationRedirectUrl()));
    }

    /**
     * Sets the URL ({@code null} = unchanged, blank = cleared). Empty when the realm does not exist;
     * {@link InvalidRedirectException} when the URL is not on a registered redirect origin of the realm.
     */
    @Transactional
    public Optional<Settings> update(final String realmId, final String postRegistrationRedirectUrl) {
        final Optional<RealmConfig> realm = realm(realmId);
        if (realm.isEmpty()) {
            return Optional.empty();
        }
        final RealmConfig cfg = realm.get();
        if (postRegistrationRedirectUrl != null) {
            final String url = postRegistrationRedirectUrl.strip();
            if (url.isEmpty()) {
                cfg.setPostRegistrationRedirectUrl(null);
            } else {
                final String problem = problem(url, registeredOrigins(realmId));
                if (problem != null) {
                    throw new InvalidRedirectException(problem);
                }
                cfg.setPostRegistrationRedirectUrl(url);
            }
            realms.save(cfg);
        }
        return Optional.of(new Settings(cfg.getPostRegistrationRedirectUrl()));
    }

    /** The realm's URL when it is still on a registered redirect origin; else empty (and a warning). */
    @Transactional(readOnly = true)
    public Optional<String> postRegistrationRedirect(final String realmId) {
        final String url = realm(realmId).map(RealmConfig::getPostRegistrationRedirectUrl).orElse(null);
        if (url == null || url.isBlank()) {
            return Optional.empty();
        }
        if (problem(url, registeredOrigins(realmId)) != null) {
            LOG.warn("Realm {}: postRegistrationRedirectUrl is no longer on a registered redirect origin; not used",
                    LogSafe.sanitize(realmId));
            return Optional.empty();
        }
        return Optional.of(url);
    }

    /** The origins of every redirect URI registered for a live client of the realm. */
    Set<String> registeredOrigins(final String realmId) {
        final Set<String> origins = new TreeSet<>();
        for (final ServiceProviderOAuthClient client : clients.findAllByRealmIdAndDeleted(realmId, false)) {
            for (final String uri : client.getRedirectUris()) {
                final String origin = origin(uri.strip());
                if (origin != null) {
                    origins.add(origin);
                }
            }
        }
        return origins;
    }

    /** Why {@code url} is not acceptable, or null when it is (package-visible for tests). */
    static String problem(final String url, final Set<String> registeredOrigins) {
        if (url.length() > MAX_LENGTH) {
            return "The URL is longer than " + MAX_LENGTH + " characters.";
        }
        final String origin = origin(url);
        if (origin == null) {
            return "Use an absolute http(s) URL without user info.";
        }
        if (!registeredOrigins.contains(origin)) {
            return "The URL must be on one of the realm's registered redirect origins (" + String.join(", ",
                    registeredOrigins) + ").";
        }
        return null;
    }

    /** {@code scheme://host[:port]} of an absolute http(s) URL (default port dropped), else null. */
    static String origin(final String url) {
        try {
            final URI uri = new URI(url);
            final String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!"http".equals(scheme) && !"https".equals(scheme) || uri.getHost() == null || uri.getRawUserInfo() != null) {
                return null;
            }
            final int port = uri.getPort();
            final boolean defaultPort = port == -1 || "https".equals(scheme) && port == 443 || "http".equals(scheme) && port == 80;
            return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + (defaultPort ? "" : ":" + port);
        } catch (final URISyntaxException e) {
            return null;
        }
    }

    private Optional<RealmConfig> realm(final String realmId) {
        return realmId == null ? Optional.empty() : realms.findById(realmId);
    }

    /** The registration settings of a realm. */
    public record Settings(String postRegistrationRedirectUrl) {
    }

    /** The URL is not acceptable; the message says why. */
    public static final class InvalidRedirectException extends RuntimeException {
        public InvalidRedirectException(final String message) {
            super(message);
        }
    }
}
