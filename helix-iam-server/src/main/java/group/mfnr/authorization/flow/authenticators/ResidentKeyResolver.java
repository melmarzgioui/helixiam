package group.mfnr.authorization.flow.authenticators;

import java.util.Optional;

/**
 * Helix IAM (10) Passwordless: resolves the owning user of a usernameless / resident-key WebAuthn assertion
 * <em>and</em> verifies its signature in one step. The flow engine has no established user yet (there is no
 * prior password step), so the discoverable credential identifies who is signing in. Returns the resolved
 * userId only when the assertion verifies — otherwise empty, so the authenticator can fail closed.
 *
 * <p>Decoupled from AMQP so {@link PasswordlessLoginAuthenticator} is unit-testable; the live binding is
 * {@code AmqpResidentKeyResolver}.
 */
@FunctionalInterface
public interface ResidentKeyResolver {

    /**
     * @param input a JSON blob packing the browser assertion (credentialId/userHandle/authenticatorData/
     *              clientDataJSON/signature, base64url) plus the server challenge, origin and rpId
     * @return the verified credential owner's userId, or empty when the assertion is unknown/invalid
     */
    Optional<String> resolveAndVerify(String input);
}
