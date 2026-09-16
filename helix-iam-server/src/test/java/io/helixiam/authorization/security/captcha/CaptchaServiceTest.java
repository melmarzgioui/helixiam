package io.helixiam.authorization.security.captcha;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Auth-hardening (feature 5): the per-realm CAPTCHA hook with a stubbed verifier. */
class CaptchaServiceTest {

    private RealmSettingsDto withCaptcha(final String provider, final String site, final String secret) {
        return new RealmSettingsDto("gov", "gov", null, 3600, 5_184_000, false, false, 12, true,
                1_800, 36_000, false, 2_592_000,
                false, 5, 900, 900, false,
                false, false, false, false, false, 0,
                false, provider, site, secret, 0, true, false, 40, 70, "allow", "step_up", "deny",
                null, null, null, null, null, true);
    }

    @Test
    void disabledProvider_isNoOp_andAlwaysVerifies() {
        final RealmSettingsResolver resolver = mock(RealmSettingsResolver.class);
        when(resolver.get("gov")).thenReturn(withCaptcha("none", null, null));
        final CaptchaVerifier verifier = (p, s, t, ip) -> { throw new AssertionError("must not be called"); };
        final CaptchaService service = new CaptchaService(resolver, verifier);

        assertThat(service.isEnabled("gov")).isFalse();
        assertThat(service.siteKey("gov")).isNull();
        assertThat(service.verify("gov", null, "1.2.3.4")).isTrue();
    }

    @Test
    void enabledProvider_delegatesToVerifier() {
        final RealmSettingsResolver resolver = mock(RealmSettingsResolver.class);
        when(resolver.get("gov")).thenReturn(withCaptcha("turnstile", "site-123", "secret-xyz"));
        final boolean[] called = {false};
        final CaptchaVerifier verifier = (provider, secret, token, ip) -> {
            called[0] = true;
            assertThat(provider).isEqualTo("turnstile");
            assertThat(secret).isEqualTo("secret-xyz");
            assertThat(token).isEqualTo("tok");
            return true;
        };
        final CaptchaService service = new CaptchaService(resolver, verifier);

        assertThat(service.isEnabled("gov")).isTrue();
        assertThat(service.siteKey("gov")).isEqualTo("site-123");
        assertThat(service.verify("gov", "tok", "1.2.3.4")).isTrue();
        assertThat(called[0]).isTrue();
    }

    @Test
    void enabledProvider_failsClosed_whenVerifierRejects() {
        final RealmSettingsResolver resolver = mock(RealmSettingsResolver.class);
        when(resolver.get("gov")).thenReturn(withCaptcha("recaptcha", "site", "secret"));
        final CaptchaService service = new CaptchaService(resolver, (p, s, t, ip) -> false);
        assertThat(service.verify("gov", "bad-token", null)).isFalse();
    }
}
