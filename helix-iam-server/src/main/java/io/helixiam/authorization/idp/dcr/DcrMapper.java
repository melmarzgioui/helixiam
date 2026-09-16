package io.helixiam.authorization.idp.dcr;

import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientWriteDto;

import java.util.List;
import java.util.UUID;

/**
 * Helix IAM E11: pure mapping between RFC 7591 client metadata and the Helix {@link ClientWriteDto} that
 * flows over the client-admin AMQP path, and back from the stored {@link ClientDto} to the RFC 7591
 * response. {@code client_id} is server-generated; {@code public}/secret is inferred from the requested
 * {@code token_endpoint_auth_method} ({@code none} ⇒ public client, no secret).
 */
public final class DcrMapper {

    /** Default grant per RFC 7591 §2 when the request omits {@code grant_types}. */
    static final List<String> DEFAULT_GRANT_TYPES = List.of("authorization_code");
    static final List<String> DEFAULT_RESPONSE_TYPES = List.of("code");
    static final String DEFAULT_AUTH_METHOD = "client_secret_basic";

    private DcrMapper() {
    }

    /** Map an inbound registration to a Helix client write payload with a generated {@code client_id}. */
    public static ClientWriteDto toWrite(final String realmId, final ClientRegistrationRequest request) {
        final String clientId = "dcr-" + UUID.randomUUID();
        final String authMethod = request.tokenEndpointAuthMethod() == null || request.tokenEndpointAuthMethod().isBlank()
                ? DEFAULT_AUTH_METHOD : request.tokenEndpointAuthMethod();
        final boolean publicClient = "none".equalsIgnoreCase(authMethod);
        final List<String> grantTypes = request.grantTypes() == null || request.grantTypes().isEmpty()
                ? DEFAULT_GRANT_TYPES : request.grantTypes();
        return new ClientWriteDto(realmId, null, clientId, grantTypes, nullToEmpty(request.redirectUris()),
                scopeList(request.scope()), null, null, request.clientName(), null,
                nullToEmpty(request.postLogoutRedirectUris()), null, publicClient, null, null, null, null, null, null,
                null, null, null, null, null, authMethod, request.jwksUri(), null, null, null,
                null, null, null);
    }

    /** Build the RFC 7591 client-information response from the stored client + management credentials. */
    public static ClientRegistrationResponse toResponse(final ClientDto client, final String registrationAccessToken,
                                                         final String registrationClientUri) {
        return new ClientRegistrationResponse(
                client.clientId(), client.secret(), registrationAccessToken, registrationClientUri,
                client.name(), client.redirectUris(), client.grantTypes(), DEFAULT_RESPONSE_TYPES,
                client.tokenEndpointAuthMethod() == null ? DEFAULT_AUTH_METHOD : client.tokenEndpointAuthMethod(),
                joinScopes(client.scopes()), client.postLogoutRedirectUris(), client.jwksUrl());
    }

    private static List<String> nullToEmpty(final List<String> value) {
        return value == null ? List.of() : value;
    }

    /** RFC 7591 {@code scope} is a single space-delimited string; Helix stores a list. */
    static List<String> scopeList(final String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }
        return List.of(scope.trim().split("\\s+"));
    }

    static String joinScopes(final List<String> scopes) {
        return scopes == null || scopes.isEmpty() ? null : String.join(" ", scopes);
    }
}
