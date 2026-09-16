/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.realm.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E8.5-S4: subscriber-side view of a realm's settings (two-copy DTO; mirrors the publisher's
 * {@code amqp.realm.RealmSettingsDto}). The persistence side of the console's Realm settings screen.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RealmSettingsDto(String realmId, String displayName, String issuer, int accessTokenTtlSeconds,
                               int refreshTokenTtlSeconds, boolean reuseRefreshTokens, boolean requireMfa,
                               int passwordMinLength, boolean enabled,
                               int ssoSessionIdleTimeoutSeconds, int ssoSessionMaxLifetimeSeconds,
                               boolean rememberMe, int rememberMeLifetimeSeconds,
                               // Auth-hardening: account lockout / brute-force.
                               boolean lockoutEnabled, int maxLoginFailures, int lockoutDurationSeconds,
                               int failureResetSeconds, boolean permanentLockout,
                               // Auth-hardening: password policy.
                               boolean passwordRequireUppercase, boolean passwordRequireLowercase,
                               boolean passwordRequireDigit, boolean passwordRequireSpecial,
                               boolean passwordNotUsername, int passwordHistoryCount,
                               // Auth-hardening: breached-password (HIBP).
                               boolean breachedPasswordCheck,
                               // Auth-hardening: CAPTCHA (secretKey is write-only — never returned on get).
                               String captchaProvider, String captchaSiteKey, String captchaSecretKey,
                               // Auth-hardening: concurrent-session limit.
                               int maxConcurrentSessions, boolean concurrentSessionEvictOldest,
                               // Adaptive risk-based authentication (default OFF).
                               boolean riskPolicyEnabled, int riskMediumThreshold, int riskHighThreshold,
                               String riskLowAction, String riskMediumAction, String riskHighAction,
                               // B2: per-realm login theming/branding (all optional; null/blank → built-in defaults).
                               String logoUrl, String primaryColor, String backgroundColor,
                               String welcomeText, String customCss,
                               // Per-realm self-registration switch (default true; ANDed with the global master flag).
                               boolean registrationEnabled) {
}
