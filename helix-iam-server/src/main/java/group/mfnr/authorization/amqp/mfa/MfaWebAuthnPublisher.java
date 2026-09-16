package group.mfnr.authorization.amqp.mfa;


/**
 * Helix IAM E3.3: WebAuthn registration against the subscriber (which verifies the attestation and stores
 * the credential) over AMQP. Second-factor login assertions use the generic credential exchange; (10)
 * passwordless usernameless (resident-key) login assertions resolve+verify here, returning the discovered
 * userId so the flow engine can establish the user without a username.
 */
public interface MfaWebAuthnPublisher {

    String EXCHANGE_AUTHORIZATION_WEBAUTHN = "exchange-authorization-webauthn";
    String WEBAUTHN_REGISTER = "authorization.webauthn.register";
    // (10) usernameless login: fully dot-delimited to match the subscriber's dash→dot binding
    // (authorization-webauthn-login-resident).
    String WEBAUTHN_LOGIN_RESIDENT = "authorization.webauthn.login.resident";

    Boolean register(final WebAuthnRegistration registration);

    /** Resolve+verify a usernameless resident-key assertion; returns the owning userId, or {@code null}. */
    String loginResident(final WebAuthnResidentAssertion assertion);
}
