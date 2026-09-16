package io.helixiam.authorization.controller.admin.io;

import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM: the single source of truth for which fields are secrets and how they are masked in a realm
 * export. A masked secret is set to {@code null} (omitted from the document) rather than carrying a
 * placeholder, so a round-tripped import never writes a fake credential. The federation config map is
 * masked by key-name heuristic (any key containing one of {@link #SECRET_CONFIG_KEY_HINTS}).
 *
 * <p>Masked on export:
 * <ul>
 *   <li>{@code ClientDto.secret} — OAuth client secret (already null on list/get; defensively nulled)</li>
 *   <li>{@code RealmSettingsDto.captchaSecretKey} — CAPTCHA secret (write-only; defensively nulled)</li>
 *   <li>{@code IdentityProviderConfig.config[*]} — any entry whose key looks like a secret
 *       (clientSecret, bindCredential, password, privateKey, secret, token, scimToken, ...)</li>
 * </ul>
 * Not secrets (kept): SAML {@code signingCertificate} / {@code encryptionCertificate} are public X.509
 * certs used for signature verification / encryption, never private keys — they stay in the export so an
 * import is self-contained. Realm signing keys are owned by the subscriber's key store and are never part
 * of this document at all.
 */
public final class SecretMasking {

    /** Substrings (lower-cased) that mark a federation config-map key as carrying a secret. */
    public static final Set<String> SECRET_CONFIG_KEY_HINTS = Set.of(
            "secret", "password", "credential", "privatekey", "private_key",
            "token", "apikey", "api_key", "clientkey", "client_key", "passphrase");

    private SecretMasking() {
    }

    /** Returns the client with its secret stripped. */
    public static ClientDto mask(final ClientDto c) {
        if (c == null || c.secret() == null) {
            return c;
        }
        return new ClientDto(c.realmId(), c.id(), c.clientId(), c.grantTypes(), c.redirectUris(), c.scopes(),
                null, c.subjectClaim(), c.authFlowAlias(), c.name(), c.description(), c.postLogoutRedirectUris(),
                c.webOrigins(), c.publicClient(), c.consentRequired(), c.displayOnConsentScreen(), c.loginTheme(),
                c.rootUrl(), c.homeUrl(), c.adminUrl(), c.alwaysDisplayInConsole(), c.accessTokenLifespan(),
                c.refreshTokenLifespan(), c.idTokenSignatureAlg(), c.reuseRefreshTokens(),
                c.tokenEndpointAuthMethod(), c.jwksUrl(), c.backchannelLogoutUri(), c.frontchannelLogoutUri(),
                c.applicationId(),
                c.x509CertificateBoundAccessTokens(), c.requireSignedRequestObject(), c.jarmResponseMode());
    }

    /** Returns the realm settings with the CAPTCHA secret stripped. */
    public static RealmSettingsDto mask(final RealmSettingsDto r) {
        if (r == null || r.captchaSecretKey() == null) {
            return r;
        }
        return new RealmSettingsDto(r.realmId(), r.displayName(), r.issuer(), r.accessTokenTtlSeconds(),
                r.refreshTokenTtlSeconds(), r.reuseRefreshTokens(), r.requireMfa(), r.passwordMinLength(),
                r.enabled(), r.ssoSessionIdleTimeoutSeconds(), r.ssoSessionMaxLifetimeSeconds(), r.rememberMe(),
                r.rememberMeLifetimeSeconds(), r.lockoutEnabled(), r.maxLoginFailures(), r.lockoutDurationSeconds(),
                r.failureResetSeconds(), r.permanentLockout(), r.passwordRequireUppercase(),
                r.passwordRequireLowercase(), r.passwordRequireDigit(), r.passwordRequireSpecial(),
                r.passwordNotUsername(), r.passwordHistoryCount(), r.breachedPasswordCheck(), r.captchaProvider(),
                r.captchaSiteKey(), null, r.maxConcurrentSessions(), r.concurrentSessionEvictOldest(),
                r.riskPolicyEnabled(), r.riskMediumThreshold(), r.riskHighThreshold(), r.riskLowAction(),
                r.riskMediumAction(), r.riskHighAction(),
                r.logoUrl(), r.primaryColor(), r.backgroundColor(), r.welcomeText(), r.customCss(),
                r.registrationEnabled());
    }

    /** Returns the identity-provider config with any secret-looking config-map entries dropped. */
    public static IdentityProviderConfig mask(final IdentityProviderConfig idp) {
        if (idp == null || idp.config() == null || idp.config().isEmpty()) {
            return idp;
        }
        final Map<String, String> safe = new LinkedHashMap<>();
        idp.config().forEach((k, v) -> {
            if (!isSecretKey(k)) {
                safe.put(k, v);
            }
        });
        return new IdentityProviderConfig(idp.realmId(), idp.alias(), idp.protocol(), idp.displayName(),
                idp.enabled(), safe);
    }

    /**
     * v2 export: like {@link #mask(IdentityProviderConfig)} but instead of dropping a secret config entry,
     * replaces its value with a {@code ${HELIX_<realm>_idp_<alias>_<key>}} placeholder and records the
     * env-var name in {@code requiredEnv}, so the secret round-trips through the environment on import.
     */
    public static IdentityProviderConfig maskToPlaceholders(final IdentityProviderConfig idp,
                                                            final java.util.Set<String> requiredEnv) {
        if (idp == null || idp.config() == null || idp.config().isEmpty()) {
            return idp;
        }
        final Map<String, String> out = new LinkedHashMap<>();
        idp.config().forEach((k, v) -> {
            if (isSecretKey(k) && v != null && !v.isBlank()) {
                final String name = SecretPlaceholders.nameFor(idp.realmId(), "idp", idp.alias(), k);
                requiredEnv.add(name);
                out.put(k, "${" + name + "}");
            } else {
                out.put(k, v);
            }
        });
        return new IdentityProviderConfig(idp.realmId(), idp.alias(), idp.protocol(), idp.displayName(),
                idp.enabled(), out);
    }

    /**
     * v2 export: like {@link #mask(RealmSettingsDto)} but, when a CAPTCHA is configured, replaces the
     * secret with a {@code ${HELIX_<realm>_captcha_secret}} placeholder (recorded in {@code requiredEnv})
     * rather than nulling it.
     */
    public static RealmSettingsDto maskToPlaceholders(final RealmSettingsDto r,
                                                      final java.util.Set<String> requiredEnv) {
        if (r == null) {
            return null;
        }
        final boolean captchaConfigured = (r.captchaSecretKey() != null && !r.captchaSecretKey().isBlank())
                || (r.captchaSiteKey() != null && !r.captchaSiteKey().isBlank());
        if (!captchaConfigured) {
            return mask(r);
        }
        final String name = SecretPlaceholders.nameFor(r.realmId(), "captcha", "secret");
        requiredEnv.add(name);
        return new RealmSettingsDto(r.realmId(), r.displayName(), r.issuer(), r.accessTokenTtlSeconds(),
                r.refreshTokenTtlSeconds(), r.reuseRefreshTokens(), r.requireMfa(), r.passwordMinLength(),
                r.enabled(), r.ssoSessionIdleTimeoutSeconds(), r.ssoSessionMaxLifetimeSeconds(), r.rememberMe(),
                r.rememberMeLifetimeSeconds(), r.lockoutEnabled(), r.maxLoginFailures(), r.lockoutDurationSeconds(),
                r.failureResetSeconds(), r.permanentLockout(), r.passwordRequireUppercase(),
                r.passwordRequireLowercase(), r.passwordRequireDigit(), r.passwordRequireSpecial(),
                r.passwordNotUsername(), r.passwordHistoryCount(), r.breachedPasswordCheck(), r.captchaProvider(),
                r.captchaSiteKey(), "${" + name + "}", r.maxConcurrentSessions(), r.concurrentSessionEvictOldest(),
                r.riskPolicyEnabled(), r.riskMediumThreshold(), r.riskHighThreshold(), r.riskLowAction(),
                r.riskMediumAction(), r.riskHighAction(),
                r.logoUrl(), r.primaryColor(), r.backgroundColor(), r.welcomeText(), r.customCss(),
                r.registrationEnabled());
    }

    /** Whether a federation config-map key looks like it holds a secret and must be masked. */
    public static boolean isSecretKey(final String key) {
        if (key == null) {
            return false;
        }
        final String lower = key.toLowerCase(Locale.ROOT);
        for (final String hint : SECRET_CONFIG_KEY_HINTS) {
            if (lower.contains(hint)) {
                return true;
            }
        }
        return false;
    }
}
