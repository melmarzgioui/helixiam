/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.realm;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.realm.admin.RealmSettingsDto;
import io.helixiam.authorization.service.RealmService;
import io.helixiam.authorization.service.client.ConsoleClientBootstrapService;
import io.helixiam.authorization.service.flow.AuthFlowService;
import io.helixiam.authorization.service.role.DefaultRolesBootstrapService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Helix IAM E8.5-S4: realm settings administration — read and persist the per-realm knobs
 * (branding, token lifetimes, refresh reuse, MFA requirement, password policy, enabled) over the
 * existing {@link RealmService}. Reads fall back to platform defaults; saves upsert so a realm that
 * only existed transiently is materialised on first edit.
 */
@Service
public class RealmAdminService {

    private static final Logger LOG = LogManager.getLogger(RealmAdminService.class);

    private final RealmService realmService;
    private final RealmAdminBootstrapService realmAdminBootstrapService;
    private final AuthFlowService authFlowService;
    private final DefaultRolesBootstrapService defaultRolesBootstrapService;
    private final ConsoleClientBootstrapService consoleClientBootstrapService;

    @Autowired
    public RealmAdminService(final RealmService realmService,
                             final RealmAdminBootstrapService realmAdminBootstrapService,
                             final AuthFlowService authFlowService,
                             final DefaultRolesBootstrapService defaultRolesBootstrapService,
                             final ConsoleClientBootstrapService consoleClientBootstrapService) {
        this.realmService = realmService;
        this.realmAdminBootstrapService = realmAdminBootstrapService;
        this.authFlowService = authFlowService;
        this.defaultRolesBootstrapService = defaultRolesBootstrapService;
        this.consoleClientBootstrapService = consoleClientBootstrapService;
    }

    /** The realm's settings, or platform defaults when no row exists yet. */
    public RealmSettingsDto get(final String realmId) {
        return toDto(realmService.getOrDefault(realmId));
    }

    /**
     * Whether the realm is actually provisioned (a {@code realm_config} row exists). Unlike {@link #get},
     * this does <b>not</b> synthesize defaults — it answers the raw existence question the realm-routing
     * filter needs to 404 unknown realms (Keycloak parity) instead of serving a synthesized discovery doc.
     */
    public boolean exists(final String realmId) {
        return realmService.exists(realmId);
    }

    /** Persists every settable field (upsert). A realm created here is bootstrapped with a browser flow + admin. */
    @Transactional
    public RealmSettingsDto save(final RealmSettingsDto dto) {
        final boolean isNewRealm = !realmService.exists(dto.realmId());
        final RealmConfig config = realmService.getOrDefault(dto.realmId());
        config.setRealmId(dto.realmId());
        config.setDisplayName(dto.displayName());
        config.setIssuer(blankToNull(dto.issuer()));
        config.setAccessTokenTtlSeconds(dto.accessTokenTtlSeconds());
        config.setRefreshTokenTtlSeconds(dto.refreshTokenTtlSeconds());
        config.setReuseRefreshTokens(dto.reuseRefreshTokens());
        config.setRequireMfa(dto.requireMfa());
        config.setPasswordMinLength(dto.passwordMinLength());
        config.setEnabled(dto.enabled());
        config.setSsoSessionIdleTimeoutSeconds(dto.ssoSessionIdleTimeoutSeconds());
        config.setSsoSessionMaxLifetimeSeconds(dto.ssoSessionMaxLifetimeSeconds());
        config.setRememberMe(dto.rememberMe());
        config.setRememberMeLifetimeSeconds(dto.rememberMeLifetimeSeconds());
        // Auth-hardening: account lockout.
        config.setLockoutEnabled(dto.lockoutEnabled());
        config.setMaxLoginFailures(dto.maxLoginFailures());
        config.setLockoutDurationSeconds(dto.lockoutDurationSeconds());
        config.setFailureResetSeconds(dto.failureResetSeconds());
        config.setPermanentLockout(dto.permanentLockout());
        // Auth-hardening: password policy.
        config.setPasswordRequireUppercase(dto.passwordRequireUppercase());
        config.setPasswordRequireLowercase(dto.passwordRequireLowercase());
        config.setPasswordRequireDigit(dto.passwordRequireDigit());
        config.setPasswordRequireSpecial(dto.passwordRequireSpecial());
        config.setPasswordNotUsername(dto.passwordNotUsername());
        config.setPasswordHistoryCount(dto.passwordHistoryCount());
        // Auth-hardening: breached-password.
        config.setBreachedPasswordCheck(dto.breachedPasswordCheck());
        // Auth-hardening: CAPTCHA — secret is write-only, so only overwrite when a new one is supplied.
        config.setCaptchaProvider(dto.captchaProvider() == null || dto.captchaProvider().isBlank() ? "none" : dto.captchaProvider());
        config.setCaptchaSiteKey(blankToNull(dto.captchaSiteKey()));
        if (dto.captchaSecretKey() != null && !dto.captchaSecretKey().isBlank()) {
            config.setCaptchaSecretKey(dto.captchaSecretKey().trim());
        }
        // Auth-hardening: concurrent-session limit.
        config.setMaxConcurrentSessions(dto.maxConcurrentSessions());
        config.setConcurrentSessionEvictOldest(dto.concurrentSessionEvictOldest());
        config.setRiskPolicyEnabled(dto.riskPolicyEnabled());
        config.setRiskMediumThreshold(dto.riskMediumThreshold());
        config.setRiskHighThreshold(dto.riskHighThreshold());
        config.setRiskLowAction(dto.riskLowAction() == null || dto.riskLowAction().isBlank() ? "allow" : dto.riskLowAction());
        config.setRiskMediumAction(dto.riskMediumAction() == null || dto.riskMediumAction().isBlank() ? "step_up" : dto.riskMediumAction());
        config.setRiskHighAction(dto.riskHighAction() == null || dto.riskHighAction().isBlank() ? "deny" : dto.riskHighAction());
        // B2: per-realm login theming (all optional → null when blank so the login page falls back to defaults).
        config.setLogoUrl(blankToNull(dto.logoUrl()));
        config.setPrimaryColor(blankToNull(dto.primaryColor()));
        config.setBackgroundColor(blankToNull(dto.backgroundColor()));
        config.setWelcomeText(blankToNull(dto.welcomeText()));
        config.setCustomCss(blankToNull(dto.customCss()));
        config.setRegistrationEnabled(dto.registrationEnabled());
        final RealmConfig saved = realmService.save(config);
        if (isNewRealm) {
            // A brand-new realm gets the built-in browser login flow, the curated default roles
            // (admin/user/auditor + admin-permission grants), and an admin user — so it's never created
            // without a way in and always has a coherent, Keycloak/WSO2-class role set.
            authFlowService.ensureBrowserFlow(dto.realmId());
            // ensureRealmAdmin first — it creates the tenant row that default roles FK to (user_roles.tenant_id).
            realmAdminBootstrapService.ensureRealmAdmin(dto.realmId());
            defaultRolesBootstrapService.ensureDefaultRoles(dto.realmId());
            // Seed the standard helix-console OIDC client so the new realm's admin can log into the
            // console via SSO (and can't be locked out for lack of a client).
            consoleClientBootstrapService.ensureConsoleClient(dto.realmId());
            LOG.info("Bootstrapped new realm {} with browser flow + admin + default roles + console client", dto.realmId());
        }
        LOG.debug("Saved realm settings for {}", dto.realmId());
        return toDto(saved);
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private RealmSettingsDto toDto(final RealmConfig c) {
        return new RealmSettingsDto(c.getRealmId(), c.getDisplayName(), c.getIssuer(), c.getAccessTokenTtlSeconds(),
                c.getRefreshTokenTtlSeconds(), c.isReuseRefreshTokens(), c.isRequireMfa(), c.getPasswordMinLength(),
                c.isEnabled(), c.getSsoSessionIdleTimeoutSeconds(), c.getSsoSessionMaxLifetimeSeconds(),
                c.isRememberMe(), c.getRememberMeLifetimeSeconds(),
                c.isLockoutEnabled(), c.getMaxLoginFailures(), c.getLockoutDurationSeconds(),
                c.getFailureResetSeconds(), c.isPermanentLockout(),
                c.isPasswordRequireUppercase(), c.isPasswordRequireLowercase(), c.isPasswordRequireDigit(),
                c.isPasswordRequireSpecial(), c.isPasswordNotUsername(), c.getPasswordHistoryCount(),
                c.isBreachedPasswordCheck(),
                // captchaSecretKey: returned over the internal AMQP seam so the publisher can verify tokens
                // server-side; the console-facing controller strips it so it never reaches the browser.
                c.getCaptchaProvider() == null ? "none" : c.getCaptchaProvider(), c.getCaptchaSiteKey(),
                c.getCaptchaSecretKey(),
                c.getMaxConcurrentSessions(), c.isConcurrentSessionEvictOldest(),
                c.isRiskPolicyEnabled(), c.getRiskMediumThreshold(), c.getRiskHighThreshold(),
                c.getRiskLowAction(), c.getRiskMediumAction(), c.getRiskHighAction(),
                c.getLogoUrl(), c.getPrimaryColor(), c.getBackgroundColor(), c.getWelcomeText(), c.getCustomCss(),
                c.isRegistrationEnabled());
    }
}
