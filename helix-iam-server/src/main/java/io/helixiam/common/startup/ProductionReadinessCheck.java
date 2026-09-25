/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.startup;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

/**
 * Startup guard for the server's security posture.
 *
 * <p>Outside the {@code dev} profile the server <b>refuses to start</b> when a setting would make a
 * production deployment unsafe by accident:
 * <ul>
 *   <li>{@code DB_ENCRYPTION} unset — realm signing keys and TOTP secrets would be stored in
 *       plaintext. Set the key, or explicitly accept the risk with {@code HELIX_ALLOW_PLAINTEXT_SECRETS=true}.</li>
 *   <li>{@code IDP_BASE_URL} / {@code SP_BASE_URL} unset — the server would otherwise fall back to
 *       placeholder URLs and mint tokens/redirects for the wrong host.</li>
 * </ul>
 *
 * <p>It always logs a one-line "production readiness" summary of any remaining insecure-but-allowed
 * setting so operators can see the posture at a glance. The {@code dev} profile downgrades every
 * fatal check to an informational note.
 */
@Component
public class ProductionReadinessCheck {

    private static final Logger LOG = LoggerFactory.getLogger(ProductionReadinessCheck.class);

    private final boolean devProfile;
    private final String encryptionKey;
    private final boolean allowPlaintextSecrets;
    private final String idpBaseUrl;
    private final String spBaseUrl;
    private final boolean registrationEnabled;
    private final boolean prometheusAnonymous;
    private final boolean cookieSecure;
    private final boolean springdocPublic;
    private final boolean egressAllowPrivate;

    public ProductionReadinessCheck(
            final Environment env,
            @Value("${database.encryption:}") final String encryptionKey,
            @Value("${helix.allow-plaintext-secrets:false}") final boolean allowPlaintextSecrets,
            @Value("${idp.base.url:}") final String idpBaseUrl,
            @Value("${sp.base.url:}") final String spBaseUrl,
            @Value("${user.register.enabled:false}") final boolean registrationEnabled,
            @Value("${helix.actuator.prometheus-anonymous:false}") final boolean prometheusAnonymous,
            @Value("${helix.security.cookie-secure:true}") final boolean cookieSecure,
            @Value("${helix.springdoc.public:false}") final boolean springdocPublic,
            @Value("${helix.egress.allow-private:false}") final boolean egressAllowPrivate) {
        this.devProfile = Arrays.asList(env.getActiveProfiles()).contains("dev");
        this.encryptionKey = encryptionKey;
        this.allowPlaintextSecrets = allowPlaintextSecrets;
        this.idpBaseUrl = idpBaseUrl;
        this.spBaseUrl = spBaseUrl;
        this.registrationEnabled = registrationEnabled;
        this.prometheusAnonymous = prometheusAnonymous;
        this.cookieSecure = cookieSecure;
        this.springdocPublic = springdocPublic;
        this.egressAllowPrivate = egressAllowPrivate;
    }

    @PostConstruct
    void check() {
        final List<String> fatal = new ArrayList<>();
        final List<String> insecure = new ArrayList<>();

        final boolean encryptionOff = isBlank(encryptionKey);
        if (encryptionOff) {
            if (devProfile || allowPlaintextSecrets) {
                insecure.add("at-rest secret encryption DISABLED (DB_ENCRYPTION unset) — signing keys "
                        + "and TOTP secrets are stored in plaintext");
            } else {
                fatal.add("DB_ENCRYPTION is not set: realm signing keys and TOTP secrets would be stored "
                        + "in PLAINTEXT. Set DB_ENCRYPTION, or set HELIX_ALLOW_PLAINTEXT_SECRETS=true to "
                        + "accept the risk explicitly.");
            }
        }
        if (!devProfile) {
            if (isBlank(idpBaseUrl)) {
                fatal.add("IDP_BASE_URL is not set: the server needs its own external base URL "
                        + "(issuer, broker callbacks).");
            }
            if (isBlank(spBaseUrl)) {
                fatal.add("SP_BASE_URL is not set: the server needs the console/SP origin (CORS, redirects).");
            }
        }

        if (registrationEnabled) {
            insecure.add("platform-wide self-registration ENABLED (USER_REGISTRATION_ENABLED=true)");
        }
        if (prometheusAnonymous) {
            insecure.add("/actuator/prometheus is ANONYMOUS — restrict it at the network layer or set "
                    + "HELIX_ACTUATOR_PROMETHEUS_ANONYMOUS=false");
        }
        if (!cookieSecure && !devProfile) {
            insecure.add("session/CSRF cookies are NOT marked Secure (HELIX_COOKIE_SECURE=false)");
        }
        if (springdocPublic) {
            insecure.add("OpenAPI/Swagger is PUBLIC (HELIX_API_DOCS_PUBLIC=true)");
        }
        if (egressAllowPrivate) {
            insecure.add("SSRF egress guard relaxed to allow private/loopback (HELIX_EGRESS_ALLOW_PRIVATE=true)");
        }

        if (!fatal.isEmpty()) {
            final String msg = "HelixIAM refuses to start with an unsafe configuration:\n  - "
                    + String.join("\n  - ", fatal)
                    + "\nRun with the 'dev' Spring profile for local development.";
            LOG.error(msg);
            throw new IllegalStateException(msg);
        }

        if (insecure.isEmpty()) {
            LOG.info("Production readiness: no insecure settings detected.");
        } else {
            LOG.warn("Production readiness — {} insecure setting(s) in effect:\n  - {}",
                    insecure.size(), String.join("\n  - ", insecure));
        }
    }

    private static boolean isBlank(final String s) {
        return s == null || s.isBlank();
    }
}
