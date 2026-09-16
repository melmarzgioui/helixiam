package group.mfnr.authorization.security.device;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Story 4 (CLI auth): converts a public-client (no-secret) request that carries only a {@code client_id} into a
 * public-client authentication token, so {@link DeviceClientAuthenticationProvider} can authenticate it. Covers
 * BOTH legs of the RFC 8628 device flow that a public client makes with no credentials:
 * <ol>
 *   <li>POST {@code /oauth2/device_authorization} (start) — carries {@code client_id}.</li>
 *   <li>POST {@code /oauth2/token} with {@code grant_type=urn:ietf:params:oauth:grant-type:device_code} (poll).</li>
 * </ol>
 *
 * <p>It also covers a public client's <b>Pushed Authorization Request</b> (RFC 9126 §2): POST
 * {@code /oauth2/par} carrying {@code client_id} (+ PKCE {@code code_challenge}) with no secret. SAS's own
 * public-client converter only activates for a PKCE <em>token</em> request, so without this a public client
 * (e.g. a PKCE SPA / CLI) gets {@code invalid_client} at PAR. FAPI2 explicitly allows public-client PAR.
 *
 * <p>Every other request returns {@code null} so the default SAS converters keep handling secret / JWT / mTLS
 * clients (they run first, so a confidential client authenticating with a secret is unaffected). Paths are
 * matched app-relative, so this works under the realm-prefixed virtual context path.
 */
public final class DeviceClientAuthenticationConverter implements AuthenticationConverter {

    private static final String DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
    private static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";

    private final RequestMatcher deviceClientRequestMatcher;

    public DeviceClientAuthenticationConverter(final String deviceAuthorizationEndpointUri,
                                               final String tokenEndpointUri) {
        this(deviceAuthorizationEndpointUri, tokenEndpointUri, null);
    }

    public DeviceClientAuthenticationConverter(final String deviceAuthorizationEndpointUri,
                                               final String tokenEndpointUri,
                                               final String pushedAuthorizationRequestEndpointUri) {
        final RequestMatcher clientIdParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;
        final RequestMatcher deviceAuthorizationRequest = new AndRequestMatcher(
                new AntPathRequestMatcher(deviceAuthorizationEndpointUri, HttpMethod.POST.name()),
                clientIdParameterMatcher);
        // A public client authenticates at the token endpoint with only client_id (no secret, no PKCE
        // code_verifier) for the grants SAS's default converters don't cover: the device-code poll and the
        // refresh-token renewal. (The authorization_code + PKCE exchange IS handled by SAS's own converter.)
        final RequestMatcher publicTokenGrantRequest = new AndRequestMatcher(
                new AntPathRequestMatcher(tokenEndpointUri, HttpMethod.POST.name()),
                request -> {
                    final String grant = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
                    return DEVICE_CODE_GRANT_TYPE.equals(grant) || REFRESH_TOKEN_GRANT_TYPE.equals(grant);
                },
                clientIdParameterMatcher);
        if (StringUtils.hasText(pushedAuthorizationRequestEndpointUri)) {
            // Public-client PAR (RFC 9126 / FAPI2): POST /oauth2/par with only client_id (PKCE-secured, no secret).
            final RequestMatcher pushedAuthorizationRequest = new AndRequestMatcher(
                    new AntPathRequestMatcher(pushedAuthorizationRequestEndpointUri, HttpMethod.POST.name()),
                    clientIdParameterMatcher);
            this.deviceClientRequestMatcher = new OrRequestMatcher(
                    deviceAuthorizationRequest, publicTokenGrantRequest, pushedAuthorizationRequest);
        } else {
            this.deviceClientRequestMatcher = new OrRequestMatcher(deviceAuthorizationRequest, publicTokenGrantRequest);
        }
    }

    @Override
    public Authentication convert(final HttpServletRequest request) {
        if (!this.deviceClientRequestMatcher.matches(request)) {
            return null;
        }

        final MultiValueMap<String, String> parameters = toMultiValueMap(request);

        // client_id (REQUIRED, and exactly one)
        final String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
        }

        final Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.CLIENT_ID)) {
                additionalParameters.put(key, value.size() == 1 ? value.get(0) : value.toArray(new String[0]));
            }
        });

        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null,
                additionalParameters);
    }

    private static MultiValueMap<String, String> toMultiValueMap(final HttpServletRequest request) {
        final MultiValueMap<String, String> parameters = new org.springframework.util.LinkedMultiValueMap<>();
        request.getParameterMap().forEach((key, values) -> {
            for (final String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
