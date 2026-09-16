package io.helixiam.authorization.security.resource;

import io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * RFC 8707: the token customizer reads the {@code resource} param and sets a mutable {@code aud}, and
 * leaves the default audience untouched when no {@code resource} is requested.
 */
class ResourceIndicatorTokenCustomizerTest {

    private static RegisteredClient client() {
        return RegisteredClient.withId("id")
                .clientId("svc-client")
                .clientSecret("{noop}secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .build();
    }

    /** A client_credentials token request carrying a {@code resource} additional parameter. */
    private static JwtEncodingContext contextWithResource(final Object resourceValue) {
        final Map<String, Object> additional = resourceValue == null
                ? Map.of() : Map.of("resource", resourceValue);
        final OAuth2ClientCredentialsAuthenticationToken grant = new OAuth2ClientCredentialsAuthenticationToken(
                new UsernamePasswordAuthenticationToken("svc-client", null), Set.of("read"), additional);
        return JwtEncodingContext.with(JwsHeader.with(() -> "RS256"),
                        JwtClaimsSet.builder()
                                .subject("svc-client")
                                .audience(List.of("svc-client")) // SAS default audience = client id
                                .issuedAt(Instant.now())
                                .expiresAt(Instant.now().plusSeconds(3600)))
                .registeredClient(client())
                .principal(new UsernamePasswordAuthenticationToken("svc-client", null))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(grant)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
    }

    @Test
    void noResourceLeavesDefaultAudienceUnchanged() {
        final ResourceIndicatorPublisher publisher = mock(ResourceIndicatorPublisher.class);
        final JwtEncodingContext ctx = contextWithResource(null);

        ResourceIndicatorTokenCustomizer.applyResourceIndicators(ctx, publisher);

        final List<String> aud = ctx.getClaims().build().getAudience();
        assertThat(aud).containsExactly("svc-client"); // UNCHANGED default audience
    }

    @Test
    void requestedAllowedResourceSetsAudience() {
        final ResourceIndicatorPublisher publisher = mock(ResourceIndicatorPublisher.class);
        when(publisher.allowedResourcesForClient(io.helixiam.authorization.support.RealmScopedKey.pack("master", "svc-client")))
                .thenReturn(List.of("https://api.example.com"));
        final JwtEncodingContext ctx = contextWithResource("https://api.example.com");

        ResourceIndicatorTokenCustomizer.applyResourceIndicators(ctx, publisher);

        assertThat(ctx.getClaims().build().getAudience()).containsExactly("https://api.example.com");
    }

    @Test
    void noAllowListAcceptsAnyValidResource() {
        final ResourceIndicatorPublisher publisher = mock(ResourceIndicatorPublisher.class);
        when(publisher.allowedResourcesForClient(io.helixiam.authorization.support.RealmScopedKey.pack("master", "svc-client"))).thenReturn(List.of()); // no allow-list
        final JwtEncodingContext ctx = contextWithResource("https://anything.example.com");

        ResourceIndicatorTokenCustomizer.applyResourceIndicators(ctx, publisher);

        assertThat(ctx.getClaims().build().getAudience()).containsExactly("https://anything.example.com");
    }

    @Test
    void disallowedResourceDoesNotWidenAudience() {
        final ResourceIndicatorPublisher publisher = mock(ResourceIndicatorPublisher.class);
        when(publisher.allowedResourcesForClient(io.helixiam.authorization.support.RealmScopedKey.pack("master", "svc-client")))
                .thenReturn(List.of("https://api.example.com"));
        final JwtEncodingContext ctx = contextWithResource("https://evil.example.com");

        ResourceIndicatorTokenCustomizer.applyResourceIndicators(ctx, publisher);

        // Defensive: a disallowed resource is NOT applied — default audience kept.
        assertThat(ctx.getClaims().build().getAudience()).containsExactly("svc-client");
    }

    @Test
    void resourceIgnoredForIdToken() {
        final ResourceIndicatorPublisher publisher = mock(ResourceIndicatorPublisher.class);
        final OAuth2ClientCredentialsAuthenticationToken grant = new OAuth2ClientCredentialsAuthenticationToken(
                new UsernamePasswordAuthenticationToken("svc-client", null), Set.of("read"),
                Map.of("resource", "https://api.example.com"));
        final JwtEncodingContext idCtx = JwtEncodingContext.with(JwsHeader.with(() -> "RS256"),
                        JwtClaimsSet.builder()
                                .subject("svc-client")
                                .audience(List.of("svc-client"))
                                .issuedAt(Instant.now())
                                .expiresAt(Instant.now().plusSeconds(3600)))
                .registeredClient(client())
                .principal(new UsernamePasswordAuthenticationToken("svc-client", null))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(grant)
                .tokenType(new OAuth2TokenType("id_token"))
                .build();

        ResourceIndicatorTokenCustomizer.applyResourceIndicators(idCtx, publisher);

        assertThat(idCtx.getClaims().build().getAudience()).containsExactly("svc-client");
    }

    @Test
    void multipleResourceValuesAllSetAsAudience() {
        final ResourceIndicatorPublisher publisher = mock(ResourceIndicatorPublisher.class);
        when(publisher.allowedResourcesForClient(io.helixiam.authorization.support.RealmScopedKey.pack("master", "svc-client"))).thenReturn(List.of());
        final JwtEncodingContext ctx = contextWithResource(
                List.of("https://a.example.com", "https://b.example.com"));

        ResourceIndicatorTokenCustomizer.applyResourceIndicators(ctx, publisher);

        assertThat(ctx.getClaims().build().getAudience())
                .containsExactly("https://a.example.com", "https://b.example.com");
    }
}
