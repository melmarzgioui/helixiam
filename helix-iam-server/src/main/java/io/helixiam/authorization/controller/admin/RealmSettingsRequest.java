package io.helixiam.authorization.controller.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;

/**
 * Helix IAM E8.5-S4: the editable realm-settings payload from the console (realmId comes from the path).
 * Auth-hardening adds the account-lockout, password-policy, breached-password, CAPTCHA and
 * concurrent-session knobs.
 */
public record RealmSettingsRequest(@NotBlank(message = "Display name is required.") String displayName,
                                   String issuer,
                                   @Positive(message = "Access-token TTL must be greater than zero.") int accessTokenTtlSeconds,
                                   @Positive(message = "Refresh-token TTL must be greater than zero.") int refreshTokenTtlSeconds,
                                   boolean reuseRefreshTokens, boolean requireMfa,
                                   @PositiveOrZero(message = "Password minimum length cannot be negative.") int passwordMinLength, boolean enabled,
                                   @PositiveOrZero(message = "SSO session idle timeout cannot be negative.") int ssoSessionIdleTimeoutSeconds,
                                   @PositiveOrZero(message = "SSO session max lifetime cannot be negative.") int ssoSessionMaxLifetimeSeconds,
                                   boolean rememberMe,
                                   @PositiveOrZero(message = "Remember-me lifetime cannot be negative.") int rememberMeLifetimeSeconds,
                                   // Auth-hardening: account lockout / brute-force.
                                   boolean lockoutEnabled,
                                   @PositiveOrZero(message = "Max login failures cannot be negative.") int maxLoginFailures,
                                   @PositiveOrZero(message = "Lockout duration cannot be negative.") int lockoutDurationSeconds,
                                   @PositiveOrZero(message = "Failure-reset window cannot be negative.") int failureResetSeconds,
                                   boolean permanentLockout,
                                   // Auth-hardening: password policy.
                                   boolean passwordRequireUppercase, boolean passwordRequireLowercase,
                                   boolean passwordRequireDigit, boolean passwordRequireSpecial,
                                   boolean passwordNotUsername,
                                   @PositiveOrZero(message = "Password history count cannot be negative.") int passwordHistoryCount,
                                   // Auth-hardening: breached-password (HIBP).
                                   boolean breachedPasswordCheck,
                                   // Auth-hardening: CAPTCHA (secretKey is write-only).
                                   String captchaProvider, String captchaSiteKey, String captchaSecretKey,
                                   // Auth-hardening: concurrent-session limit.
                                   @PositiveOrZero(message = "Max concurrent sessions cannot be negative.") int maxConcurrentSessions,
                                   boolean concurrentSessionEvictOldest,
                                   // Adaptive risk-based authentication (default OFF).
                                   boolean riskPolicyEnabled,
                                   @PositiveOrZero(message = "Risk medium threshold cannot be negative.") int riskMediumThreshold,
                                   @PositiveOrZero(message = "Risk high threshold cannot be negative.") int riskHighThreshold,
                                   String riskLowAction, String riskMediumAction, String riskHighAction,
                                   // B2: per-realm login theming/branding (all optional).
                                   String logoUrl, String primaryColor, String backgroundColor,
                                   String welcomeText, String customCss,
                                   // Per-realm self-registration switch.
                                   boolean registrationEnabled) {
}
