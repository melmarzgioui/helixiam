/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.realm;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

/**
 * Per-realm configuration (Helix IAM E1.3).
 *
 * <p>A realm maps 1:1 to a tenant ({@code realmId == tenantId}); this entity is additive
 * over the existing tenant model. It carries the per-realm knobs that later epics build on:
 * token lifetimes, refresh-token reuse, issuer override, MFA requirement, password policy
 * and branding. Per-realm signing keys are added in E1.4.
 */
@Entity
@Table(name = "realm_config")
@EntityListeners(AuditingEntityListener.class)
public class RealmConfig {

    /** Conventional id of the bootstrap/administration realm. */
    public static final String ADMIN_REALM_ID = "master";

    public static final int DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 3600;          // 1 hour
    public static final int DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 5_184_000;    // 60 days
    public static final int DEFAULT_PASSWORD_MIN_LENGTH = 12;
    // SSO P3: per-realm SSO session policy defaults (seconds).
    public static final int DEFAULT_SSO_SESSION_IDLE_TIMEOUT_SECONDS = 1_800;     // 30 min idle
    public static final int DEFAULT_SSO_SESSION_MAX_LIFETIME_SECONDS = 36_000;    // 10 h hard cap
    public static final int DEFAULT_REMEMBER_ME_LIFETIME_SECONDS = 2_592_000;     // 30 days

    // Auth-hardening: account-lockout / brute-force defaults.
    public static final int DEFAULT_MAX_LOGIN_FAILURES = 5;
    public static final int DEFAULT_LOCKOUT_DURATION_SECONDS = 900;       // 15 min
    public static final int DEFAULT_FAILURE_RESET_SECONDS = 900;          // 15 min sliding window

    @Id
    @Column(name = "realm_id")
    @JsonProperty
    private String realmId;

    @Column(name = "display_name")
    @JsonProperty
    private String displayName;

    /** Optional issuer override; {@code null} = auto-detect from the request. */
    @Column(name = "issuer")
    @JsonProperty
    private String issuer;

    @Column(name = "access_token_ttl_seconds")
    @JsonProperty
    private int accessTokenTtlSeconds = DEFAULT_ACCESS_TOKEN_TTL_SECONDS;

    @Column(name = "refresh_token_ttl_seconds")
    @JsonProperty
    private int refreshTokenTtlSeconds = DEFAULT_REFRESH_TOKEN_TTL_SECONDS;

    @Column(name = "reuse_refresh_tokens")
    @JsonProperty
    private boolean reuseRefreshTokens = false;

    @Column(name = "require_mfa")
    @JsonProperty
    private boolean requireMfa = false;

    @Column(name = "password_min_length")
    @JsonProperty
    private int passwordMinLength = DEFAULT_PASSWORD_MIN_LENGTH;

    /** Catalogue claim key whose value populates the OIDC {@code sub}; {@code null} = the {@code sub} claim itself. */
    @Column(name = "subject_claim")
    @JsonProperty
    private String subjectClaim;

    @Column(name = "enabled")
    @JsonProperty
    private boolean enabled = true;

    // SSO P3: per-realm SSO session policies.
    @Column(name = "sso_session_idle_timeout_seconds")
    @JsonProperty
    private int ssoSessionIdleTimeoutSeconds = DEFAULT_SSO_SESSION_IDLE_TIMEOUT_SECONDS;

    @Column(name = "sso_session_max_lifetime_seconds")
    @JsonProperty
    private int ssoSessionMaxLifetimeSeconds = DEFAULT_SSO_SESSION_MAX_LIFETIME_SECONDS;

    @Column(name = "remember_me")
    @JsonProperty
    private boolean rememberMe = false;

    @Column(name = "remember_me_lifetime_seconds")
    @JsonProperty
    private int rememberMeLifetimeSeconds = DEFAULT_REMEMBER_ME_LIFETIME_SECONDS;

    // --- Auth-hardening: account lockout / brute-force protection ---
    @Column(name = "lockout_enabled")
    @JsonProperty
    private boolean lockoutEnabled = false;

    @Column(name = "max_login_failures")
    @JsonProperty
    private int maxLoginFailures = DEFAULT_MAX_LOGIN_FAILURES;

    @Column(name = "lockout_duration_seconds")
    @JsonProperty
    private int lockoutDurationSeconds = DEFAULT_LOCKOUT_DURATION_SECONDS;

    @Column(name = "failure_reset_seconds")
    @JsonProperty
    private int failureResetSeconds = DEFAULT_FAILURE_RESET_SECONDS;

    /** When the threshold is hit, lock the account permanently (admin unlock required) instead of for a window. */
    @Column(name = "permanent_lockout")
    @JsonProperty
    private boolean permanentLockout = false;

    // --- Auth-hardening: password policy ---
    @Column(name = "password_require_uppercase")
    @JsonProperty
    private boolean passwordRequireUppercase = false;

    @Column(name = "password_require_lowercase")
    @JsonProperty
    private boolean passwordRequireLowercase = false;

    @Column(name = "password_require_digit")
    @JsonProperty
    private boolean passwordRequireDigit = false;

    @Column(name = "password_require_special")
    @JsonProperty
    private boolean passwordRequireSpecial = false;

    @Column(name = "password_not_username")
    @JsonProperty
    private boolean passwordNotUsername = false;

    @Column(name = "password_history_count")
    @JsonProperty
    private int passwordHistoryCount = 0;

    // --- Auth-hardening: breached-password (HIBP) detection ---
    @Column(name = "breached_password_check")
    @JsonProperty
    private boolean breachedPasswordCheck = false;

    // --- Auth-hardening: CAPTCHA ---
    /** {@code none}, {@code turnstile} or {@code recaptcha}. */
    @Column(name = "captcha_provider")
    @JsonProperty
    private String captchaProvider = "none";

    @Column(name = "captcha_site_key")
    @JsonProperty
    private String captchaSiteKey;

    /** Write-only secret; never serialised back to the console. */
    @Column(name = "captcha_secret_key")
    @JsonProperty
    private String captchaSecretKey;

    // --- Auth-hardening: concurrent-session limit ---
    /** Max concurrent SSO sessions per user; {@code 0} = unlimited. */
    @Column(name = "max_concurrent_sessions")
    @JsonProperty
    private int maxConcurrentSessions = 0;

    /** {@code true} = evict the oldest session, {@code false} = deny the new login when the cap is hit. */
    @Column(name = "concurrent_session_evict_oldest")
    @JsonProperty
    private boolean concurrentSessionEvictOldest = true;

    // --- Adaptive risk-based authentication (default OFF → login unchanged) ---
    @Column(name = "risk_policy_enabled")
    @JsonProperty
    private boolean riskPolicyEnabled = false;

    @Column(name = "risk_medium_threshold")
    @JsonProperty
    private int riskMediumThreshold = 40;

    @Column(name = "risk_high_threshold")
    @JsonProperty
    private int riskHighThreshold = 70;

    @Column(name = "risk_low_action")
    @JsonProperty
    private String riskLowAction = "allow";

    @Column(name = "risk_medium_action")
    @JsonProperty
    private String riskMediumAction = "step_up";

    @Column(name = "risk_high_action")
    @JsonProperty
    private String riskHighAction = "deny";

    // B2: per-realm login theming/branding (all optional; null/blank → built-in KubeDNA defaults).
    @Column(name = "logo_url")
    @JsonProperty
    private String logoUrl;

    @Column(name = "primary_color")
    @JsonProperty
    private String primaryColor;

    @Column(name = "background_color")
    @JsonProperty
    private String backgroundColor;

    @Column(name = "welcome_text")
    @JsonProperty
    private String welcomeText;

    @Column(name = "custom_css", length = 8000)
    @JsonProperty
    private String customCss;

    // Per-realm self-registration switch (default true; the global master flag can still disable all realms).
    @Column(name = "registration_enabled")
    @JsonProperty
    private boolean registrationEnabled = true;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;

    public RealmConfig() {
    }

    /** Builds a transient realm config with platform defaults for the given realm id. */
    public static RealmConfig defaults(final String realmId) {
        final RealmConfig config = new RealmConfig();
        config.realmId = realmId;
        return config;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(final String displayName) {
        this.displayName = displayName;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    public int getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public void setAccessTokenTtlSeconds(final int accessTokenTtlSeconds) {
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public int getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    public void setRefreshTokenTtlSeconds(final int refreshTokenTtlSeconds) {
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public boolean isReuseRefreshTokens() {
        return reuseRefreshTokens;
    }

    public void setReuseRefreshTokens(final boolean reuseRefreshTokens) {
        this.reuseRefreshTokens = reuseRefreshTokens;
    }

    public boolean isRequireMfa() {
        return requireMfa;
    }

    public void setRequireMfa(final boolean requireMfa) {
        this.requireMfa = requireMfa;
    }

    public int getPasswordMinLength() {
        return passwordMinLength;
    }

    public void setPasswordMinLength(final int passwordMinLength) {
        this.passwordMinLength = passwordMinLength;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public String getSubjectClaim() {
        return subjectClaim;
    }

    public void setSubjectClaim(final String subjectClaim) {
        this.subjectClaim = subjectClaim;
    }

    public int getSsoSessionIdleTimeoutSeconds() {
        return ssoSessionIdleTimeoutSeconds;
    }

    public void setSsoSessionIdleTimeoutSeconds(final int ssoSessionIdleTimeoutSeconds) {
        this.ssoSessionIdleTimeoutSeconds = ssoSessionIdleTimeoutSeconds;
    }

    public int getSsoSessionMaxLifetimeSeconds() {
        return ssoSessionMaxLifetimeSeconds;
    }

    public void setSsoSessionMaxLifetimeSeconds(final int ssoSessionMaxLifetimeSeconds) {
        this.ssoSessionMaxLifetimeSeconds = ssoSessionMaxLifetimeSeconds;
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(final boolean rememberMe) {
        this.rememberMe = rememberMe;
    }

    public int getRememberMeLifetimeSeconds() {
        return rememberMeLifetimeSeconds;
    }

    public void setRememberMeLifetimeSeconds(final int rememberMeLifetimeSeconds) {
        this.rememberMeLifetimeSeconds = rememberMeLifetimeSeconds;
    }

    public boolean isLockoutEnabled() {
        return lockoutEnabled;
    }

    public void setLockoutEnabled(final boolean lockoutEnabled) {
        this.lockoutEnabled = lockoutEnabled;
    }

    public int getMaxLoginFailures() {
        return maxLoginFailures;
    }

    public void setMaxLoginFailures(final int maxLoginFailures) {
        this.maxLoginFailures = maxLoginFailures;
    }

    public int getLockoutDurationSeconds() {
        return lockoutDurationSeconds;
    }

    public void setLockoutDurationSeconds(final int lockoutDurationSeconds) {
        this.lockoutDurationSeconds = lockoutDurationSeconds;
    }

    public int getFailureResetSeconds() {
        return failureResetSeconds;
    }

    public void setFailureResetSeconds(final int failureResetSeconds) {
        this.failureResetSeconds = failureResetSeconds;
    }

    public boolean isPermanentLockout() {
        return permanentLockout;
    }

    public void setPermanentLockout(final boolean permanentLockout) {
        this.permanentLockout = permanentLockout;
    }

    public boolean isPasswordRequireUppercase() {
        return passwordRequireUppercase;
    }

    public void setPasswordRequireUppercase(final boolean passwordRequireUppercase) {
        this.passwordRequireUppercase = passwordRequireUppercase;
    }

    public boolean isPasswordRequireLowercase() {
        return passwordRequireLowercase;
    }

    public void setPasswordRequireLowercase(final boolean passwordRequireLowercase) {
        this.passwordRequireLowercase = passwordRequireLowercase;
    }

    public boolean isPasswordRequireDigit() {
        return passwordRequireDigit;
    }

    public void setPasswordRequireDigit(final boolean passwordRequireDigit) {
        this.passwordRequireDigit = passwordRequireDigit;
    }

    public boolean isPasswordRequireSpecial() {
        return passwordRequireSpecial;
    }

    public void setPasswordRequireSpecial(final boolean passwordRequireSpecial) {
        this.passwordRequireSpecial = passwordRequireSpecial;
    }

    public boolean isPasswordNotUsername() {
        return passwordNotUsername;
    }

    public void setPasswordNotUsername(final boolean passwordNotUsername) {
        this.passwordNotUsername = passwordNotUsername;
    }

    public int getPasswordHistoryCount() {
        return passwordHistoryCount;
    }

    public void setPasswordHistoryCount(final int passwordHistoryCount) {
        this.passwordHistoryCount = passwordHistoryCount;
    }

    public boolean isBreachedPasswordCheck() {
        return breachedPasswordCheck;
    }

    public void setBreachedPasswordCheck(final boolean breachedPasswordCheck) {
        this.breachedPasswordCheck = breachedPasswordCheck;
    }

    public String getCaptchaProvider() {
        return captchaProvider;
    }

    public void setCaptchaProvider(final String captchaProvider) {
        this.captchaProvider = captchaProvider;
    }

    public String getCaptchaSiteKey() {
        return captchaSiteKey;
    }

    public void setCaptchaSiteKey(final String captchaSiteKey) {
        this.captchaSiteKey = captchaSiteKey;
    }

    public String getCaptchaSecretKey() {
        return captchaSecretKey;
    }

    public void setCaptchaSecretKey(final String captchaSecretKey) {
        this.captchaSecretKey = captchaSecretKey;
    }

    public int getMaxConcurrentSessions() {
        return maxConcurrentSessions;
    }

    public void setMaxConcurrentSessions(final int maxConcurrentSessions) {
        this.maxConcurrentSessions = maxConcurrentSessions;
    }

    public boolean isConcurrentSessionEvictOldest() {
        return concurrentSessionEvictOldest;
    }

    public void setConcurrentSessionEvictOldest(final boolean concurrentSessionEvictOldest) {
        this.concurrentSessionEvictOldest = concurrentSessionEvictOldest;
    }

    public boolean isRiskPolicyEnabled() {
        return riskPolicyEnabled;
    }

    public void setRiskPolicyEnabled(final boolean riskPolicyEnabled) {
        this.riskPolicyEnabled = riskPolicyEnabled;
    }

    public int getRiskMediumThreshold() {
        return riskMediumThreshold;
    }

    public void setRiskMediumThreshold(final int riskMediumThreshold) {
        this.riskMediumThreshold = riskMediumThreshold;
    }

    public int getRiskHighThreshold() {
        return riskHighThreshold;
    }

    public void setRiskHighThreshold(final int riskHighThreshold) {
        this.riskHighThreshold = riskHighThreshold;
    }

    public String getRiskLowAction() {
        return riskLowAction;
    }

    public void setRiskLowAction(final String riskLowAction) {
        this.riskLowAction = riskLowAction;
    }

    public String getRiskMediumAction() {
        return riskMediumAction;
    }

    public void setRiskMediumAction(final String riskMediumAction) {
        this.riskMediumAction = riskMediumAction;
    }

    public String getRiskHighAction() {
        return riskHighAction;
    }

    public void setRiskHighAction(final String riskHighAction) {
        this.riskHighAction = riskHighAction;
    }

    // B2: branding getters/setters.
    public String getLogoUrl() {
        return logoUrl;
    }

    public void setLogoUrl(final String logoUrl) {
        this.logoUrl = logoUrl;
    }

    public String getPrimaryColor() {
        return primaryColor;
    }

    public void setPrimaryColor(final String primaryColor) {
        this.primaryColor = primaryColor;
    }

    public String getBackgroundColor() {
        return backgroundColor;
    }

    public void setBackgroundColor(final String backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

    public String getWelcomeText() {
        return welcomeText;
    }

    public void setWelcomeText(final String welcomeText) {
        this.welcomeText = welcomeText;
    }

    public String getCustomCss() {
        return customCss;
    }

    public void setCustomCss(final String customCss) {
        this.customCss = customCss;
    }

    public boolean isRegistrationEnabled() {
        return registrationEnabled;
    }

    public void setRegistrationEnabled(final boolean registrationEnabled) {
        this.registrationEnabled = registrationEnabled;
    }
}
