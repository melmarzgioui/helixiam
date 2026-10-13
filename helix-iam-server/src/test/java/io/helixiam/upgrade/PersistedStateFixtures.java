/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.upgrade;

import io.helixiam.authorization.security.AuthorizationBlobs;
import io.helixiam.authorization.security.SessionBlobs;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.servlet.FlashMap;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The object graphs HelixIAM persists with Java serialization: an {@link OAuth2Authorization} (the queue and Redis
 * token stores) and an HTTP session's attribute map (the queue and Redis session stores). Deterministic, so a blob
 * written by one release can be compared field by field after another release reads it.
 *
 * <p>{@link #main} writes the blobs; it was run once on the 1.0 line (Spring Boot 3.5.16 / Spring Security 6.5.11 /
 * Spring Authorization Server 1.5.8) to produce {@code src/test/resources/upgrade/boot3/*.b64}, which
 * {@link PersistedStateUpgradeCompatibilityTest} reads on the current line. The same source compiles on both lines.
 */
public final class PersistedStateFixtures {

    static final Instant ISSUED = Instant.parse("2026-10-01T10:00:00Z");
    static final Instant EXPIRES = Instant.parse("2026-10-01T10:05:00Z");
    static final String FLASH_MAPS = "org.springframework.web.servlet.support.SessionFlashMapManager.FLASH_MAPS";

    private PersistedStateFixtures() {
    }

    /** A completed authorization-code grant: code, access, refresh and ID token, request and principal attributes. */
    public static OAuth2Authorization authorization() {
        final RegisteredClient client = RegisteredClient.withId("client-1").clientId("web")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://app.monthfold.com/cb").scope("openid").scope("profile").build();
        final Set<String> scopes = new LinkedHashSet<>(List.of("openid", "profile"));
        final OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.monthfold.com/realms/monthfold/oauth2/authorize")
                .clientId("web").redirectUri("https://app.monthfold.com/cb").scopes(scopes).state("state-xyz")
                .additionalParameters(Map.of("nonce", "n-1")).build();
        final Map<String, Object> idClaims = new HashMap<>();
        idClaims.put("iss", "https://auth.monthfold.com/realms/monthfold");
        idClaims.put("sub", "ada");
        idClaims.put("aud", List.of("web"));
        idClaims.put("sid", "sid-1");
        idClaims.put("acr", "urn:helix:acr:mfa");
        idClaims.put("auth_time", 1_790_000_000L); // epoch seconds, as IdTokenSessionClaims writes it
        return OAuth2Authorization.withRegisteredClient(client)
                .id("auth-1").principalName("ada")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(scopes)
                .attribute(OAuth2ParameterNames.STATE, "state-xyz")
                .attribute(OAuth2AuthorizationRequest.class.getName(), request)
                .attribute(Principal.class.getName(), authenticated())
                .token(new OAuth2AuthorizationCode("code-1", ISSUED, EXPIRES),
                        metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-1", ISSUED, EXPIRES, scopes),
                        metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                Map.of("sub", "ada", "scope", List.of("openid", "profile"), "realm", "monthfold")))
                .refreshToken(new OAuth2RefreshToken("refresh-1", ISSUED, EXPIRES.plusSeconds(3600)))
                .token(new OidcIdToken("id-1", ISSUED, EXPIRES, idClaims),
                        metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idClaims))
                .build();
    }

    /** What a signed-in browser session holds: security context (MFA-passed), saved request, CSRF, flash, locale. */
    public static Map<String, Object> sessionAttributes() {
        final MockHttpServletRequest authorize = new MockHttpServletRequest("GET", "/realms/monthfold/oauth2/authorize");
        authorize.setServerName("auth.monthfold.com");
        authorize.setQueryString("response_type=code&client_id=web&scope=openid");
        authorize.addParameter("response_type", "code");
        authorize.addParameter("client_id", "web");
        authorize.addHeader("Accept-Language", "nl-NL");
        authorize.addPreferredLocale(Locale.forLanguageTag("nl-NL"));

        final FlashMap flash = new FlashMap();
        flash.put("status", "password-changed");
        flash.setTargetRequestPath("/realms/monthfold/account/security");
        flash.addTargetRequestParam("tab", "password");

        final Map<String, Object> attributes = new HashMap<>();
        attributes.put("SPRING_SECURITY_CONTEXT", new SecurityContextImpl(new MfaAuthentication(authenticated())));
        attributes.put("SPRING_SECURITY_SAVED_REQUEST", new DefaultSavedRequest(authorize));
        attributes.put("org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN",
                new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-1"));
        attributes.put(FLASH_MAPS, new ArrayList<>(List.of(flash)));
        attributes.put("org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE", Locale.forLanguageTag("nl-NL"));
        attributes.put("HELIX_AUTH_TIME", 1_790_000_000L);
        attributes.put("HELIX_SID", "sid-1");
        return attributes;
    }

    /**
     * A Spring Authorization Server class whose serialized fields DID change between 1.5 and 7 ({@code claims} moved
     * out of it): the upgrade compatibility must not accept it. Never persisted by HelixIAM; a negative control only.
     */
    public static OidcClientRegistration changedClass() {
        return OidcClientRegistration.builder().clientId("web").redirectUri("https://app.monthfold.com/cb").build();
    }

    static UsernamePasswordAuthenticationToken authenticated() {
        final UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                User.withUsername("ada").password("").authorities("ROLE_user").build(), null,
                List.of(new SimpleGrantedAuthority("ROLE_user")));
        authentication.setDetails(new WebAuthenticationDetails("127.0.0.1", "session-1"));
        return authentication;
    }

    /** Writes {@code authorization.b64} and {@code session.b64} into the directory given as the first argument. */
    public static void main(final String[] args) throws IOException {
        final Path dir = Path.of(args[0]);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("authorization.b64"), AuthorizationBlobs.serialize(authorization()),
                StandardCharsets.US_ASCII);
        Files.writeString(dir.resolve("session.b64"), SessionBlobs.serialize(sessionAttributes()),
                StandardCharsets.US_ASCII);
        try (java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
             java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(bytes)) {
            out.writeObject(changedClass());
            out.flush();
            Files.writeString(dir.resolve("changed-class.b64"),
                    java.util.Base64.getEncoder().encodeToString(bytes.toByteArray()), StandardCharsets.US_ASCII);
        }
    }
}
