/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.startup;

import java.time.Clock;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import io.helixiam.authorization.federation.FederationProviderProperties;
import io.helixiam.authorization.federation.wallet.WalletProviderConfig;

import jakarta.annotation.PostConstruct;

/**
 * Startup guard for the server's security posture.
 *
 * <p>Outside the {@code dev} profile the server <b>refuses to start</b> when a setting would make a
 * production deployment unsafe by accident:
 * <ul>
 *   <li>{@code DB_ENCRYPTION} unset — realm signing keys and TOTP secrets would be stored in
 *       plaintext. Set the key, or explicitly accept the risk with {@code HELIX_ALLOW_PLAINTEXT_SECRETS=true}.</li>
 *   <li>{@code HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true} (read secret columns that still hold plaintext) without
 *       {@code HELIX_DB_ENCRYPTION_MIGRATE_UNTIL} set to a date at most 30 days ahead — the mode is time-boxed.</li>
 *   <li>{@code IDP_BASE_URL} / {@code SP_BASE_URL} unset — the server would otherwise fall back to
 *       placeholder URLs and mint tokens/redirects for the wrong host.</li>
 *   <li>Task 22: a YAML-configured EUDI Wallet ({@code helix.federation.wallet[*]}) with {@code responseMode:
 *       direct_post} (unencrypted) — allowed only in {@code dev}; outside it, {@link WalletConfigValidator} would
 *       otherwise just skip the provider silently (it throws, the factory logs and moves on), leaving the operator
 *       with a server that started but a wallet login button that is quietly missing.</li>
 *   <li>Task 22: a YAML-configured wallet provider while {@code DB_ENCRYPTION} is unset — never downgradable with
 *       {@code HELIX_ALLOW_PLAINTEXT_SECRETS}, unlike the general plaintext-secrets risk above: the wallet's peppers,
 *       transaction keys and transactions themselves all refuse to work without at-rest encryption, so starting
 *       "successfully" here would only be confusing.</li>
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
    /** Task 22: YAML wallet providers (never null; checked for direct_post and for running without encryption). */
    private final List<WalletProviderConfig> walletProviders;
    private final boolean migratePlaintext;
    private final String migrateUntil;
    private final Clock clock;
    private final List<String> lateWarnings = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** The longest a plaintext-read migration window may run (from today). */
    static final int MAX_MIGRATION_DAYS = 30;

    public ProductionReadinessCheck(final Environment env, final String encryptionKey,
                                    final boolean allowPlaintextSecrets, final String idpBaseUrl,
                                    final String spBaseUrl, final boolean registrationEnabled,
                                    final boolean prometheusAnonymous, final boolean cookieSecure,
                                    final boolean springdocPublic, final boolean egressAllowPrivate) {
        this(env, encryptionKey, allowPlaintextSecrets, idpBaseUrl, spBaseUrl, registrationEnabled, prometheusAnonymous,
                cookieSecure, springdocPublic, egressAllowPrivate, false, "", Clock.systemUTC());
    }

    @Autowired
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
            @Value("${helix.egress.allow-private:false}") final boolean egressAllowPrivate,
            @Value("${helix.security.db-encryption.migrate-plaintext:false}") final boolean migratePlaintext,
            @Value("${helix.security.db-encryption.migrate-until:}") final String migrateUntil,
            final FederationProviderProperties federation) {
        this(env, encryptionKey, allowPlaintextSecrets, idpBaseUrl, spBaseUrl, registrationEnabled, prometheusAnonymous,
                cookieSecure, springdocPublic, egressAllowPrivate, migratePlaintext, migrateUntil, Clock.systemUTC(),
                federation);
    }

    /** Task 22: the checks with YAML wallet providers ({@code helix.federation.wallet[*]}). */
    public ProductionReadinessCheck(final Environment env, final String encryptionKey,
                                    final boolean allowPlaintextSecrets, final String idpBaseUrl,
                                    final String spBaseUrl, final boolean registrationEnabled,
                                    final boolean prometheusAnonymous, final boolean cookieSecure,
                                    final boolean springdocPublic, final boolean egressAllowPrivate,
                                    final FederationProviderProperties federation) {
        this(env, encryptionKey, allowPlaintextSecrets, idpBaseUrl, spBaseUrl, registrationEnabled, prometheusAnonymous,
                cookieSecure, springdocPublic, egressAllowPrivate, false, "", Clock.systemUTC(), federation);
    }

    ProductionReadinessCheck(final Environment env, final String encryptionKey, final boolean allowPlaintextSecrets,
                             final String idpBaseUrl, final String spBaseUrl, final boolean registrationEnabled,
                             final boolean prometheusAnonymous, final boolean cookieSecure, final boolean springdocPublic,
                             final boolean egressAllowPrivate, final boolean migratePlaintext, final String migrateUntil,
                             final Clock clock) {
        this(env, encryptionKey, allowPlaintextSecrets, idpBaseUrl, spBaseUrl, registrationEnabled, prometheusAnonymous,
                cookieSecure, springdocPublic, egressAllowPrivate, migratePlaintext, migrateUntil, clock, null);
    }

    ProductionReadinessCheck(final Environment env, final String encryptionKey, final boolean allowPlaintextSecrets,
                             final String idpBaseUrl, final String spBaseUrl, final boolean registrationEnabled,
                             final boolean prometheusAnonymous, final boolean cookieSecure, final boolean springdocPublic,
                             final boolean egressAllowPrivate, final boolean migratePlaintext, final String migrateUntil,
                             final Clock clock, final FederationProviderProperties federation) {
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
        this.walletProviders = federation == null || federation.getWallet() == null ? List.of()
                : List.copyOf(federation.getWallet());
        this.migratePlaintext = migratePlaintext;
        this.migrateUntil = migrateUntil;
        this.clock = clock;
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
        if (migratePlaintext) {
            final String problem = devProfile ? null : migrationWindowProblem();
            if (problem == null) {
                insecure.add("encrypted columns that hold plaintext are READ AS PLAINTEXT "
                        + "(HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true" + (isBlank(migrateUntil) ? "" : " until " + migrateUntil)
                        + ") — it also hides a changed key. Unset it once those rows are re-encrypted");
            } else {
                fatal.add("HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true reads undecryptable secret columns as plaintext. "
                        + "It is a time-boxed migration mode: set HELIX_DB_ENCRYPTION_MIGRATE_UNTIL to the ISO date "
                        + "(yyyy-MM-dd) it ends, at most " + MAX_MIGRATION_DAYS + " days ahead (" + problem + ").");
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
            // Task 22: a direct_post wallet provider is dev-only; WalletConfigValidator refuses it too, but only by
            // skipping that one provider (logged, not fatal) — so without this check the server starts "successfully"
            // with a wallet login button that silently does not work.
            final List<String> directPost = walletProviders.stream()
                    .filter(w -> w.responseMode() == WalletProviderConfig.ResponseMode.DIRECT_POST)
                    .map(WalletProviderConfig::alias).toList();
            if (!directPost.isEmpty()) {
                fatal.add("wallet provider(s) " + directPost + " use responseMode direct_post (unencrypted), "
                        + "which is allowed only in the dev profile.");
            }
            // Task 22: a wallet provider cannot function without at-rest encryption (peppers, transaction keys and
            // transactions themselves all refuse), so — unlike the general plaintext-secrets risk below — this is
            // never downgradable with HELIX_ALLOW_PLAINTEXT_SECRETS.
            if (encryptionOff && !walletProviders.isEmpty()) {
                fatal.add("a wallet provider is configured but DB_ENCRYPTION is not set: wallet peppers, "
                        + "transaction keys and transactions themselves refuse to work without at-rest encryption.");
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
            insecure.add("SSRF egress guard relaxed to allow private/loopback for every host (HELIX_EGRESS_ALLOW_PRIVATE=true, "
                    + "deprecated) — list the internal hosts in HELIX_EGRESS_ALLOWED_PRIVATE_HOSTS instead");
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

    /**
     * An insecure condition found after startup (e.g. a failed legacy re-encryption, which runs once the application is
     * up): logged in the same "Production readiness" form as the startup WARN list and kept for
     * {@link #lateWarnings()}. Always a WARNING, never fatal: the startup check has already passed, and such a condition
     * comes from a runtime failure (a database error), not from a setting the operator can fix before starting.
     */
    public void warnAfterStartup(final String condition) {
        lateWarnings.add(condition);
        LOG.warn("Production readiness — insecure condition in effect:\n  - {}", condition);
    }

    /** The conditions reported through {@link #warnAfterStartup} since startup. */
    public List<String> lateWarnings() {
        return List.copyOf(lateWarnings);
    }

    /** Why the migration end date is not acceptable, or null when it is today .. today + 30 days. */
    private String migrationWindowProblem() {
        if (isBlank(migrateUntil)) {
            return "it is not set";
        }
        final LocalDate until;
        try {
            until = LocalDate.parse(migrateUntil.trim());
        } catch (final DateTimeParseException e) {
            return "it is not an ISO date";
        }
        final LocalDate today = LocalDate.now(clock);
        if (until.isBefore(today)) {
            return "it has passed";
        }
        if (until.isAfter(today.plusDays(MAX_MIGRATION_DAYS))) {
            return "it is more than " + MAX_MIGRATION_DAYS + " days ahead";
        }
        return null;
    }

    private static boolean isBlank(final String s) {
        return s == null || s.isBlank();
    }
}
