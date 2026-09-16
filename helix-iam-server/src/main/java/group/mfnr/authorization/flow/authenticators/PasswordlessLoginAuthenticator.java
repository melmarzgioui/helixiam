package group.mfnr.authorization.flow.authenticators;

import group.mfnr.authorization.flow.spi.AuthenticationContext;
import group.mfnr.authorization.flow.spi.Authenticator;
import group.mfnr.authorization.flow.spi.AuthenticatorMetadata;
import group.mfnr.authorization.flow.spi.FactorClass;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Helix IAM (10): passwordless, <em>usernameless</em> passkey login — a phishing-resistant first-step
 * authenticator. Unlike {@link WebAuthnAuthenticator} (a second factor that verifies against an already
 * established user), this one establishes identity from a discoverable (resident-key) credential: the
 * browser runs {@code navigator.credentials.get()} with conditional mediation and <em>no</em>
 * allowCredentials list, so the user picks a passkey and the authenticator data carries the userHandle.
 *
 * <p>{@link #authenticate} issues a server challenge (held for replay protection) and renders the page that
 * drives conditional-UI passkey discovery; {@link #action} packs the assertion + challenge and asks the
 * {@link ResidentKeyResolver} to resolve+verify it. On success the resolved user is recorded via
 * {@link AuthenticationContext#establishUser} so the rest of the flow acts on a known user — exactly as the
 * password authenticator would, but with no password and no username typed.
 */
public class PasswordlessLoginAuthenticator implements Authenticator {

    static final String VIEW = "passkey-login-form";
    static final String CHALLENGE_ATTRIBUTE = "passkey-login.challenge";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ResidentKeyResolver resolver;
    private final String rpId;
    private final String origin;

    public PasswordlessLoginAuthenticator(final ResidentKeyResolver resolver, final String rpId, final String origin) {
        this.resolver = resolver;
        this.rpId = rpId;
        this.origin = origin;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        // POSSESSION factor with high LoA — but, crucially, identity-establishing, so it is a valid FIRST step.
        return AuthenticatorMetadata.of("passkey-login", "Passwordless passkey", FactorClass.POSSESSION, 3);
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
        if (challenge == null || credentialId == null || credentialId.isBlank()) {
            context.failure("No passkey was presented");
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
        final Optional<String> userId = resolver.resolveAndVerify(input);
        if (userId.isPresent()) {
            context.establishUser(userId.get());
            context.success();
        } else {
            context.failure("Passkey not recognised");
        }
    }

    private static String nullSafe(final String value) {
        return value == null ? "" : value;
    }

    /** Minimal JSON object builder (string keys/values, JSON-escaped) — matches {@link WebAuthnAuthenticator}. */
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
