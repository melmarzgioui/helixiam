package io.helixiam.authorization.security.captcha;

/**
 * Auth-hardening (feature 5): server-side CAPTCHA token verification. Implementations call the provider's
 * verify endpoint (Cloudflare Turnstile / Google reCAPTCHA). Injectable so tests can stub it.
 */
@FunctionalInterface
public interface CaptchaVerifier {

    /**
     * @param provider {@code turnstile} or {@code recaptcha}
     * @param secretKey the realm's provider secret
     * @param token the widget response token submitted with the form
     * @param remoteIp the client IP (optional, may be {@code null})
     * @return {@code true} when the provider confirms the token
     */
    boolean verify(String provider, String secretKey, String token, String remoteIp);
}
