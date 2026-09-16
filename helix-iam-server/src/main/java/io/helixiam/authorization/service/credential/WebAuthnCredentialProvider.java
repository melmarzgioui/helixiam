package io.helixiam.authorization.service.credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.service.mfa.WebAuthnService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Helix IAM E3.3: WebAuthn/passkey as an auto-discovered {@link CredentialProvider}. The login
 * "input" is a JSON blob the publisher packs from the browser assertion plus the server challenge
 * (base64url for binary fields); this routes it to {@link WebAuthnService#verifyAssertion}.
 */
@Component
public class WebAuthnCredentialProvider implements CredentialProvider {

    private static final Logger LOG = LogManager.getLogger(WebAuthnCredentialProvider.class);

    private final WebAuthnService webAuthnService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public WebAuthnCredentialProvider(final WebAuthnService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    @Override
    public String type() {
        return "webauthn";
    }

    @Override
    public boolean verify(final String userId, final String input) {
        try {
            final JsonNode node = objectMapper.readTree(input);
            return webAuthnService.verifyAssertion(
                    userId,
                    urlDecode(node, "credentialId"),
                    urlDecode(node, "userHandle"),
                    urlDecode(node, "authenticatorData"),
                    urlDecode(node, "clientDataJSON"),
                    urlDecode(node, "signature"),
                    node.path("challenge").asText(),
                    node.path("origin").asText(),
                    node.path("rpId").asText());
        } catch (final Exception e) {
            LOG.warn("Malformed WebAuthn assertion input for user {}: {}", userId, e.getMessage());
            return false;
        }
    }

    private static byte[] urlDecode(final JsonNode node, final String field) {
        final String value = node.path(field).asText("");
        return value.isEmpty() ? new byte[0] : Base64.getUrlDecoder().decode(value);
    }
}
