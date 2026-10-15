/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.credential;

import io.helixiam.common.json.JsonMappers;
import io.helixiam.common.json.JsonNodes;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
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
    private final ObjectMapper objectMapper = JsonMappers.plain();

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
                    JsonNodes.text(node.path("challenge")),
                    JsonNodes.text(node.path("origin")),
                    JsonNodes.text(node.path("rpId")));
        } catch (final Exception e) {
            LOG.warn("Malformed WebAuthn assertion input for user {}: {}", userId, e.getMessage());
            return false;
        }
    }

    private static byte[] urlDecode(final JsonNode node, final String field) {
        final String value = JsonNodes.text(node.path(field), "");
        return value.isEmpty() ? new byte[0] : Base64.getUrlDecoder().decode(value);
    }
}
