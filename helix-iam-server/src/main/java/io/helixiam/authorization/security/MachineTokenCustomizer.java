package io.helixiam.authorization.security;

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.Collections;

/**
 * Stamps the machine (client_credentials) identity onto a token: {@code sub} and {@code aud} are pinned to
 * the requesting client id. The issuer is deliberately left untouched — the token generator has already set
 * {@code iss} to the realm issuer the AS advertises in discovery, and that is exactly what a standards-
 * compliant resource server (RFC 9068 / an MCP server) validates against. Pinning {@code sub} to the client
 * id keeps the delegation flow ({@code DelegationTokenController}) able to identify the acting agent.
 */
public final class MachineTokenCustomizer {

    private MachineTokenCustomizer() {
    }

    public static void applyMachineTokenIdentity(final JwtEncodingContext context) {
        final String clientId = context.getRegisteredClient().getClientId();
        context.getClaims().subject(clientId);
        context.getClaims().audience(Collections.singletonList(clientId));
        // NOTE: intentionally does NOT override the issuer — see class javadoc.
    }
}
