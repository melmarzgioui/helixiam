package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.FactorClass;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helix IAM E3.3: WebAuthn / passkey (FIDO2) factor. {@link #authenticate} issues a server
 * challenge (held for replay protection) and renders the page that runs
 * {@code navigator.credentials.get()}; {@link #action} packs the browser assertion plus the
 * challenge and verifies it via the generic {@link CredentialVerifier} under credential type
 * {@code "webauthn"} (the subscriber's provider checks the signature + advances the sign count).
 */
public class WebAuthnAuthenticator implements Authenticator {

    static final String VIEW = "webauthn-form";
    static final String CHALLENGE_ATTRIBUTE = "webauthn.challenge";
    static final String CREDENTIAL_TYPE = "webauthn";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final CredentialVerifier verifier;
    private final String rpId;
    private final String origin;

    public WebAuthnAuthenticator(final CredentialVerifier verifier, final String rpId, final String origin) {
        this.verifier = verifier;
        this.rpId = rpId;
        this.origin = origin;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("webauthn", "Passkey (WebAuthn)", FactorClass.POSSESSION, 3);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        final byte[] challenge = new byte[32];
        RANDOM.nextBytes(challenge);
        context.putAttribute(CHALLENGE_ATTRIBUTE, Base64.getUrlEncoder().withoutPadding().encodeToString(challenge));
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final Object challenge = context.getAttribute(CHALLENGE_ATTRIBUTE);
        final String credentialId = context.formParameter("credentialId");
        if (challenge == null || credentialId == null) {
            context.failure("Missing passkey assertion");
            return;
        }
        final String input = json(
                "credentialId", credentialId,
                "userHandle", nullSafe(context.formParameter("userHandle")),
                "authenticatorData", nullSafe(context.formParameter("authenticatorData")),
                "clientDataJSON", nullSafe(context.formParameter("clientDataJSON")),
                "signature", nullSafe(context.formParameter("signature")),
                "challenge", challenge.toString(),
                "origin", origin,
                "rpId", rpId);
        if (verifier.verify(CREDENTIAL_TYPE, context.userId(), input)) {
            context.success();
        } else {
            context.failure("Passkey verification failed");
        }
    }

    private static String nullSafe(final String value) {
        return value == null ? "" : value;
    }

    /** Minimal JSON object builder (string keys/values, JSON-escaped). */
    private static String json(final String... kv) {
        final StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(kv[i]).append("\":\"").append(escape(kv[i + 1])).append('"');
        }
        return sb.append('}').toString();
    }

    private static String escape(final String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
