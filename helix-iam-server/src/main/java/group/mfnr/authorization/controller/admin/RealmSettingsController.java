package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.realm.RealmAdminPublisher;
import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM E8.5-S4: admin REST API for a realm's settings (branding, token lifetimes, refresh reuse,
 * MFA requirement, password policy, enabled) — the backend behind the console's Realm settings screen.
 * Realm comes from the path; reads fall back to platform defaults and writes upsert.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings")
public class RealmSettingsController {

    private final RealmAdminPublisher publisher;

    public RealmSettingsController(final RealmAdminPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public RealmSettingsDto get(@PathVariable final String realmId) {
        // Auth-hardening: the CAPTCHA secret is write-only — strip it before it ever reaches the browser.
        return withoutSecret(publisher.get(realmId));
    }

    /** Nulls the write-only CAPTCHA secret so the console never receives it. */
    private static RealmSettingsDto withoutSecret(final RealmSettingsDto dto) {
        if (dto == null || dto.captchaSecretKey() == null) {
            return dto;
        }
        return new RealmSettingsDto(dto.realmId(), dto.displayName(), dto.issuer(), dto.accessTokenTtlSeconds(),
                dto.refreshTokenTtlSeconds(), dto.reuseRefreshTokens(), dto.requireMfa(), dto.passwordMinLength(),
                dto.enabled(), dto.ssoSessionIdleTimeoutSeconds(), dto.ssoSessionMaxLifetimeSeconds(),
                dto.rememberMe(), dto.rememberMeLifetimeSeconds(),
                dto.lockoutEnabled(), dto.maxLoginFailures(), dto.lockoutDurationSeconds(),
                dto.failureResetSeconds(), dto.permanentLockout(),
                dto.passwordRequireUppercase(), dto.passwordRequireLowercase(), dto.passwordRequireDigit(),
                dto.passwordRequireSpecial(), dto.passwordNotUsername(), dto.passwordHistoryCount(),
                dto.breachedPasswordCheck(),
                dto.captchaProvider(), dto.captchaSiteKey(), null,
                dto.maxConcurrentSessions(), dto.concurrentSessionEvictOldest(),
                dto.riskPolicyEnabled(), dto.riskMediumThreshold(), dto.riskHighThreshold(),
                dto.riskLowAction(), dto.riskMediumAction(), dto.riskHighAction(),
                dto.logoUrl(), dto.primaryColor(), dto.backgroundColor(), dto.welcomeText(), dto.customCss(),
                dto.registrationEnabled());
    }

    @PutMapping
    public ResponseEntity<RealmSettingsDto> save(@PathVariable final String realmId,
                                                 @Valid @RequestBody final RealmSettingsRequest request) {
        final RealmSettingsDto saved = publisher.save(new RealmSettingsDto(realmId, request.displayName(),
                request.issuer(), request.accessTokenTtlSeconds(), request.refreshTokenTtlSeconds(),
                request.reuseRefreshTokens(), request.requireMfa(), request.passwordMinLength(), request.enabled(),
                request.ssoSessionIdleTimeoutSeconds(), request.ssoSessionMaxLifetimeSeconds(),
                request.rememberMe(), request.rememberMeLifetimeSeconds(),
                request.lockoutEnabled(), request.maxLoginFailures(), request.lockoutDurationSeconds(),
                request.failureResetSeconds(), request.permanentLockout(),
                request.passwordRequireUppercase(), request.passwordRequireLowercase(),
                request.passwordRequireDigit(), request.passwordRequireSpecial(),
                request.passwordNotUsername(), request.passwordHistoryCount(),
                request.breachedPasswordCheck(),
                request.captchaProvider(), request.captchaSiteKey(), request.captchaSecretKey(),
                request.maxConcurrentSessions(), request.concurrentSessionEvictOldest(),
                request.riskPolicyEnabled(), request.riskMediumThreshold(), request.riskHighThreshold(),
                request.riskLowAction(), request.riskMediumAction(), request.riskHighAction(),
                request.logoUrl(), request.primaryColor(), request.backgroundColor(),
                request.welcomeText(), request.customCss(), request.registrationEnabled()));
        return ResponseEntity.ok(withoutSecret(saved));
    }
}
