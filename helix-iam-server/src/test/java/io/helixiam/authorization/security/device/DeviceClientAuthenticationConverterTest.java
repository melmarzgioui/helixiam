package io.helixiam.authorization.security.device;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Story 4 (CLI auth): the converter authenticates a public client (client_id only) on BOTH legs of the device
 * flow — the device_authorization start and the device_code token poll — and stays out of the way otherwise.
 */
class DeviceClientAuthenticationConverterTest {

    private static final String DEVICE_ENDPOINT = "/oauth2/device_authorization";
    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String PAR_ENDPOINT = "/oauth2/par";
    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    private DeviceClientAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        converter = new DeviceClientAuthenticationConverter(DEVICE_ENDPOINT, TOKEN_ENDPOINT, PAR_ENDPOINT);
    }

    private static HttpServletRequest post(final String uri, final String... params) {
        final MockHttpServletRequest r = new MockHttpServletRequest("POST", uri);
        r.setServletPath(uri);
        for (int i = 0; i < params.length; i += 2) {
            r.addParameter(params[i], params[i + 1]);
        }
        return r;
    }

    @Test
    void convertsDeviceAuthorizationStart() {
        final Authentication auth = converter.convert(post(DEVICE_ENDPOINT, "client_id", "kubedna-cli"));
        assertNotNull(auth);
        assertEquals("kubedna-cli", ((OAuth2ClientAuthenticationToken) auth).getPrincipal());
        assertEquals(ClientAuthenticationMethod.NONE, ((OAuth2ClientAuthenticationToken) auth).getClientAuthenticationMethod());
    }

    @Test
    void convertsDeviceCodeTokenPoll() {
        final Authentication auth = converter.convert(
                post(TOKEN_ENDPOINT, "grant_type", DEVICE_CODE_GRANT, "client_id", "kubedna-cli", "device_code", "abc"));
        assertNotNull(auth, "public client polling the token endpoint with the device_code grant is authenticated");
        assertEquals("kubedna-cli", ((OAuth2ClientAuthenticationToken) auth).getPrincipal());
    }

    @Test
    void convertsRefreshTokenGrant() {
        // A public client renews with only client_id (no secret, no PKCE) — SAS's converters don't cover this.
        final Authentication auth = converter.convert(
                post(TOKEN_ENDPOINT, "grant_type", "refresh_token", "client_id", "kubedna-cli", "refresh_token", "rt"));
        assertNotNull(auth, "public client refresh_token renewal is authenticated");
    }

    @Test
    void convertsPushedAuthorizationRequest() {
        // Public-client PAR (RFC 9126 / FAPI2): client_id + PKCE code_challenge, no secret.
        final Authentication auth = converter.convert(
                post(PAR_ENDPOINT, "client_id", "kubedna-cli", "response_type", "code",
                        "code_challenge", "abc", "code_challenge_method", "S256"));
        assertNotNull(auth, "public client pushing an authorization request is authenticated");
        assertEquals("kubedna-cli", ((OAuth2ClientAuthenticationToken) auth).getPrincipal());
        assertEquals(ClientAuthenticationMethod.NONE, ((OAuth2ClientAuthenticationToken) auth).getClientAuthenticationMethod());
    }

    @Test
    void ignoresParWhenNotConfigured() {
        // Backward-compatible 2-arg ctor: PAR not wired → converter stays out of PAR requests.
        final DeviceClientAuthenticationConverter noPar =
                new DeviceClientAuthenticationConverter(DEVICE_ENDPOINT, TOKEN_ENDPOINT);
        assertNull(noPar.convert(post(PAR_ENDPOINT, "client_id", "kubedna-cli")));
    }

    @Test
    void ignoresAuthorizationCodeGrant() {
        // authorization_code + PKCE token exchange is handled by SAS's own public/PKCE converter — not us.
        assertNull(converter.convert(
                post(TOKEN_ENDPOINT, "grant_type", "authorization_code", "client_id", "kubedna-cli", "code", "x")));
    }

    @Test
    void ignoresRequestsWithoutClientId() {
        assertNull(converter.convert(post(DEVICE_ENDPOINT)));
        assertNull(converter.convert(post(TOKEN_ENDPOINT, "grant_type", DEVICE_CODE_GRANT)));
    }

    @Test
    void ignoresUnrelatedEndpoints() {
        assertNull(converter.convert(post("/oauth2/authorize", "client_id", "kubedna-cli")));
    }
}
