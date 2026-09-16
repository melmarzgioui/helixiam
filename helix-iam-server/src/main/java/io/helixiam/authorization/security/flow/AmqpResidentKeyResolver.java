package io.helixiam.authorization.security.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.mfa.MfaWebAuthnPublisher;
import io.helixiam.authorization.amqp.mfa.WebAuthnResidentAssertion;
import io.helixiam.authorization.flow.authenticators.ResidentKeyResolver;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Helix IAM (10): live {@link ResidentKeyResolver} that forwards a usernameless resident-key assertion to the
 * subscriber over AMQP, which discovers the owning user from the credential, verifies the signature, and
 * returns the userId. Unpacks the authenticator's JSON {@code input} into the two-copy
 * {@link WebAuthnResidentAssertion} DTO. Fails closed (empty) on any malformed input or absent owner.
 */
@Component
public class AmqpResidentKeyResolver implements ResidentKeyResolver {

    private static final Logger LOG = LogManager.getLogger(AmqpResidentKeyResolver.class);

    private final MfaWebAuthnPublisher publisher;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AmqpResidentKeyResolver(final MfaWebAuthnPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public Optional<String> resolveAndVerify(final String input) {
        try {
            final JsonNode n = objectMapper.readTree(input);
            final WebAuthnResidentAssertion assertion = new WebAuthnResidentAssertion(
                    text(n, "credentialId"), text(n, "userHandle"), text(n, "authenticatorData"),
                    text(n, "clientDataJSON"), text(n, "signature"), text(n, "challenge"),
                    text(n, "origin"), text(n, "rpId"));
            final String userId = publisher.loginResident(assertion);
            return userId == null || userId.isBlank() ? Optional.empty() : Optional.of(userId);
        } catch (final Exception e) {
            LOG.warn("Malformed usernameless WebAuthn assertion input: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private static String text(final JsonNode node, final String field) {
        return node.path(field).asText("");
    }
}
