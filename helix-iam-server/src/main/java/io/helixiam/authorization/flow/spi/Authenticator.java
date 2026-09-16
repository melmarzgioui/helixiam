package io.helixiam.authorization.flow.spi;

/**
 * Helix IAM E2.1: the core extensibility point — a pluggable authentication step. The flow
 * engine references authenticators by {@link AuthenticatorMetadata#id()} and the runtime
 * (E2.4) drives them: {@link #authenticate} either completes the step or issues a challenge,
 * and {@link #action} processes the user/device response to a challenge. Built-ins: password,
 * OTP/TOTP, passkey, device-QR, …; third parties ship more as signed plugins.
 */
public interface Authenticator {

    /** Stable identity + factor + config schema (the admin console renders the schema). */
    AuthenticatorMetadata metadata();

    /**
     * Begin the step. Implementations call exactly one of {@link AuthenticationContext#success()},
     * {@link AuthenticationContext#failure(String)}, or {@link AuthenticationContext#challenge(String)}.
     */
    void authenticate(AuthenticationContext context);

    /**
     * Process the user/device response to a challenge issued by {@link #authenticate}. Defaults
     * to re-running {@code authenticate} for stateless single-shot authenticators.
     */
    default void action(final AuthenticationContext context) {
        authenticate(context);
    }

    /**
     * Whether this authenticator is usable for the given user in the given realm (e.g. OTP is
     * only configured once the user has enrolled a secret). Defaults to always usable.
     */
    default boolean configuredFor(final String realmId, final String userId) {
        return true;
    }
}
