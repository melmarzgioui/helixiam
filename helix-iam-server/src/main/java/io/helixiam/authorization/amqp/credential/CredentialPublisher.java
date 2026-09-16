package io.helixiam.authorization.amqp.credential;


/**
 * Helix IAM: one generic AMQP client for credential verification — routes to the subscriber's
 * auto-discovered provider for the given type. New credential-backed factors reuse this; no new
 * exchange/queue per factor.
 */
public interface CredentialPublisher {

    String EXCHANGE_AUTHORIZATION_CREDENTIAL = "exchange-authorization-credential";
    String CREDENTIAL_VERIFY = "authorization.credential.verify";

    Boolean verify(final CredentialVerification verification);
}
