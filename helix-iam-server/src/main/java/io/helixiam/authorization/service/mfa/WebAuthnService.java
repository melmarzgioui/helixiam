package io.helixiam.authorization.service.mfa;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import io.helixiam.authorization.domain.mfa.WebAuthnCredentialEntity;
import io.helixiam.authorization.repository.mfa.WebAuthnCredentialRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;

/**
 * Helix IAM E3.3: verifies WebAuthn/FIDO2 (passkey) registrations and login assertions via
 * webauthn4j, and owns the stored credentials. Registration parses + validates the attestation
 * and stores the attested credential data; login validates the assertion signature against the
 * stored public key and advances the sign counter (clone detection). The server challenge is
 * issued by the publisher and passed in here for replay protection.
 */
@Service
public class WebAuthnService {

    private static final Logger LOG = LogManager.getLogger(WebAuthnService.class);

    private final WebAuthnCredentialRepository repository;
    private final ObjectConverter objectConverter = new ObjectConverter();
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    private final AttestedCredentialDataConverter acdConverter = new AttestedCredentialDataConverter(objectConverter);

    public WebAuthnService(final WebAuthnCredentialRepository repository) {
        this.repository = repository;
    }

    /** Verifies a registration attestation and stores the new credential. */
    @Transactional
    public boolean finishRegistration(final String userId, final byte[] attestationObject, final byte[] clientDataJSON,
                                      final String challengeB64Url, final String origin, final String rpId) {
        try {
            final RegistrationData data = webAuthnManager.parse(new RegistrationRequest(attestationObject, clientDataJSON));
            final ServerProperty serverProperty = new ServerProperty(new Origin(origin), rpId, challenge(challengeB64Url), null);
            webAuthnManager.validate(data, new RegistrationParameters(serverProperty, false, true));

            final AttestedCredentialData acd = data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
            final long signCount = data.getAttestationObject().getAuthenticatorData().getSignCount();
            final String credentialId = base64Url(acd.getCredentialId());
            final String stored = Base64.getEncoder().encodeToString(acdConverter.convert(acd));
            repository.save(new WebAuthnCredentialEntity(credentialId, userId, stored, signCount));
            LOG.info("Registered WebAuthn credential for user {}", userId);
            return true;
        } catch (final RuntimeException e) {
            LOG.warn("WebAuthn registration failed for user {}: {}", userId, e.getMessage());
            return false;
        }
    }

    /** Verifies a login assertion against the user's stored credential, advancing the sign count. */
    @Transactional
    public boolean verifyAssertion(final String userId, final byte[] credentialId, final byte[] userHandle,
                                   final byte[] authenticatorData, final byte[] clientDataJSON, final byte[] signature,
                                   final String challengeB64Url, final String origin, final String rpId) {
        try {
            final WebAuthnCredentialEntity entity = repository.findByCredentialId(base64Url(credentialId)).orElse(null);
            if (entity == null || !entity.getUserId().equals(userId)) {
                return false;
            }
            final AttestedCredentialData acd = acdConverter.convert(Base64.getDecoder().decode(entity.getAttestedCredential()));
            final Authenticator authenticator = new AuthenticatorImpl(acd, null, entity.getSignCount());

            final AuthenticationData data = webAuthnManager.parse(
                    new AuthenticationRequest(credentialId, userHandle, authenticatorData, clientDataJSON, signature));
            final ServerProperty serverProperty = new ServerProperty(new Origin(origin), rpId, challenge(challengeB64Url), null);
            webAuthnManager.validate(data, new AuthenticationParameters(serverProperty, authenticator, false, true));

            entity.setSignCount(data.getAuthenticatorData().getSignCount());
            repository.save(entity);
            return true;
        } catch (final RuntimeException e) {
            LOG.warn("WebAuthn assertion failed for user {}: {}", userId, e.getMessage());
            return false;
        }
    }

    /**
     * Helix IAM (10) Passwordless: verifies a <em>usernameless / resident-key</em> login assertion where no
     * user is yet established. The owning user is resolved from the discoverable credential (by credentialId),
     * the assertion signature is checked against the stored public key, and the sign counter is advanced.
     * Returns the resolved {@code userId} on success, or {@code null} when the credential is unknown or the
     * assertion is invalid — so the flow engine can {@code establishUser} only on a proven passkey.
     */
    @Transactional
    public String resolveAndVerifyAssertion(final byte[] credentialId, final byte[] userHandle,
                                            final byte[] authenticatorData, final byte[] clientDataJSON,
                                            final byte[] signature, final String challengeB64Url,
                                            final String origin, final String rpId) {
        try {
            final WebAuthnCredentialEntity entity = repository.findByCredentialId(base64Url(credentialId)).orElse(null);
            if (entity == null) {
                return null;
            }
            final AttestedCredentialData acd = acdConverter.convert(Base64.getDecoder().decode(entity.getAttestedCredential()));
            final Authenticator authenticator = new AuthenticatorImpl(acd, null, entity.getSignCount());

            final AuthenticationData data = webAuthnManager.parse(
                    new AuthenticationRequest(credentialId, userHandle, authenticatorData, clientDataJSON, signature));
            final ServerProperty serverProperty = new ServerProperty(new Origin(origin), rpId, challenge(challengeB64Url), null);
            webAuthnManager.validate(data, new AuthenticationParameters(serverProperty, authenticator, false, true));

            entity.setSignCount(data.getAuthenticatorData().getSignCount());
            repository.save(entity);
            return entity.getUserId();
        } catch (final RuntimeException e) {
            LOG.warn("Usernameless WebAuthn assertion failed: {}", e.getMessage());
            return null;
        }
    }

    private DefaultChallenge challenge(final String base64Url) {
        return new DefaultChallenge(Base64.getUrlDecoder().decode(base64Url));
    }

    private static String base64Url(final byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
