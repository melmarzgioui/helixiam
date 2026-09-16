package io.helixiam.authorization.flow.authenticators;

import java.util.Optional;

/**
 * Helix IAM E2.3: verifies a username/password and resolves the user id on success. Keeps
 * {@link PasswordAuthenticator} decoupled from the AMQP {@code LoginPublisher} that performs
 * the actual credential check in the subscriber.
 */
@FunctionalInterface
public interface PasswordVerifier {

    /** The resolved user id when the credentials are valid, otherwise empty. */
    Optional<String> verify(String username, String password);
}
