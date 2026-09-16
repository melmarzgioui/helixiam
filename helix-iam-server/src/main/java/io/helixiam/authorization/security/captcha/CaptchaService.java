package io.helixiam.authorization.security.captcha;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import org.springframework.stereotype.Service;

/**
 * Auth-hardening (feature 5): the per-realm CAPTCHA hook used by the login/register/reset paths. Reads the
 * realm's provider config (none|turnstile|recaptcha + site/secret keys) and verifies a submitted token
 * server-side via the injected {@link CaptchaVerifier}. When the provider is {@code none} (the default) it
 * is a no-op that always passes, so existing flows are unchanged unless an operator enables CAPTCHA.
 */
@Service
public class CaptchaService {

    private final RealmSettingsResolver resolver;
    private final CaptchaVerifier verifier;

    public CaptchaService(final RealmSettingsResolver resolver, final CaptchaVerifier verifier) {
        this.resolver = resolver;
        this.verifier = verifier;
    }

    /** Whether the realm requires a CAPTCHA (provider configured to something other than {@code none}). */
    public boolean isEnabled(final String realmId) {
        final String provider = providerOf(realmId);
        return !"none".equalsIgnoreCase(provider);
    }

    /** The realm's public site key (for the widget), or {@code null} when CAPTCHA is off. */
    public String siteKey(final String realmId) {
        final RealmSettingsDto settings = resolver.get(realmId);
        return isEnabled(realmId) ? settings.captchaSiteKey() : null;
    }

    /** The realm's provider name ({@code none} when off). */
    public String providerOf(final String realmId) {
        final RealmSettingsDto settings = resolver.get(realmId);
        final String provider = settings.captchaProvider();
        return provider == null || provider.isBlank() ? "none" : provider;
    }

    /**
     * Verifies a submitted CAPTCHA token for a realm. Returns {@code true} when CAPTCHA is disabled
     * (no-op) or when the provider confirms the token; {@code false} when enabled and the token is
     * missing/invalid.
     */
    public boolean verify(final String realmId, final String token, final String remoteIp) {
        if (!isEnabled(realmId)) {
            return true;
        }
        final RealmSettingsDto settings = resolver.get(realmId);
        return verifier.verify(settings.captchaProvider(), settings.captchaSecretKey(), token, remoteIp);
    }
}
