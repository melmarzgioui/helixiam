package group.mfnr.authorization.security.device;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * Story 4 (CLI auth): authenticates a PUBLIC client (auth method {@code none}) at the RFC 8628 device
 * authorization endpoint by {@code client_id} alone.
 *
 * <p>Spring Authorization Server's built-in {@code PublicClientAuthenticationConverter} only activates for a
 * PKCE <em>token</em> request, so a public client cannot start the device flow with the defaults. This is the
 * canonical companion to {@link DeviceClientAuthenticationConverter} (mirrors the SAS device sample): it
 * resolves the client from the registry and confirms it is allowed to authenticate publicly.
 */
public final class DeviceClientAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final RegisteredClientRepository registeredClientRepository;

    public DeviceClientAuthenticationProvider(final RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        // Only handle public-client (none) authentication; let other providers handle secret/JWT/mTLS.
        if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }

        final String clientId = clientAuthentication.getPrincipal().toString();
        final RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidClient(OAuth2ParameterNames_CLIENT_ID);
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            throwInvalidClient("authentication_method");
        }

        return new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.NONE, null);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static final String OAuth2ParameterNames_CLIENT_ID = "client_id";

    private static void throwInvalidClient(final String parameterName) {
        final OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                "Device client authentication failed: " + parameterName, ERROR_URI);
        throw new OAuth2AuthenticationException(error);
    }
}
