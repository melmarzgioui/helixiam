package group.mfnr.authorization.security.resource;

import group.mfnr.authorization.amqp.resource.ResourceIndicatorPublisher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM (RFC 8707): set the access token's {@code aud} (audience) claim to the requested+granted
 * {@code resource} value(s) instead of the default audience.
 *
 * <p>Invoked once from {@code OAuthConfig.jwtTokenCustomizer} via
 * {@link #applyResourceIndicators(JwtEncodingContext, ResourceIndicatorPublisher)}:
 *
 * <ul>
 *   <li><b>No {@code resource} requested → no-op.</b> The default audience SAS computes (the client id)
 *       is left untouched. This keeps the OAuth hot path byte-for-byte unchanged.</li>
 *   <li>Only applies to the <b>access token</b> (per RFC 8707; the id_token audience stays the client).</li>
 *   <li>Resources are validated (absolute URI, no fragment) and allow-list-checked. The authorize-time
 *       filter ({@link ResourceIndicatorAuthorizeFilter}) is the primary rejection point that returns
 *       {@code invalid_target}; here we additionally drop any disallowed resource defensively rather than
 *       fail token issuance (the request already passed the filter).</li>
 *   <li>The {@code aud} is set from a <b>mutable</b> {@link ArrayList} — never {@code List.of}/{@code .toList()}
 *       (SAS's Jackson claim allowlist rejects immutable collections → token issuance would fail).</li>
 * </ul>
 *
 * Any failure is swallowed so token issuance never breaks on a resource-indicator lookup.
 */
public final class ResourceIndicatorTokenCustomizer {

    private static final Logger LOG = LogManager.getLogger(ResourceIndicatorTokenCustomizer.class);
    private static final String RESOURCE_PARAM = "resource";

    private ResourceIndicatorTokenCustomizer() {
    }

    /**
     * If the request carried one or more {@code resource} indicators (and they are valid + allowed for the
     * client), set the access token's {@code aud} to them. Otherwise leave the audience untouched.
     */
    public static void applyResourceIndicators(final JwtEncodingContext context,
                                               final ResourceIndicatorPublisher resourcePublisher) {
        try {
            // RFC 8707 scopes the resource indicator to the ACCESS token. id_token audience stays the client.
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }

            final List<String> requested = requestedResources(context);
            if (requested.isEmpty()) {
                return; // default-audience path — UNCHANGED.
            }

            final Collection<String> allowList = resolveAllowList(context, resourcePublisher);
            final ResourceIndicators.AudienceResult result =
                    ResourceIndicators.resolveAudience(requested, allowList);

            if (result.rejected() || result.audience().isEmpty()) {
                // A disallowed/invalid resource slipped past the authorize filter (e.g. a grant where the
                // filter could not resolve the client). Be conservative: do NOT widen the audience.
                LOG.warn("Resource indicator(s) {} not applied to aud for client {} (rejected={})",
                        requested, clientId(context), result.rejected());
                return;
            }

            // MUTABLE list — SAS Jackson token-claim allowlist rejects immutable List.of/.toList().
            context.getClaims().audience(new ArrayList<>(result.audience()));
        } catch (final Exception e) {
            LOG.warn("Resource-indicator audience customization failed, keeping default aud: {}", e.getMessage());
        }
    }

    /**
     * The {@code resource} values for this token request, from both possible sources:
     * <ul>
     *   <li>the stored {@link OAuth2AuthorizationRequest} additional parameters (authorization_code: the
     *       {@code resource} sent to {@code /oauth2/authorize});</li>
     *   <li>the grant authentication's additional parameters (token-endpoint grants such as
     *       client_credentials / refresh_token: the {@code resource} sent to {@code /oauth2/token}).</li>
     * </ul>
     * De-duplicated, insertion order preserved.
     */
    static List<String> requestedResources(final JwtEncodingContext context) {
        final Set<String> out = new LinkedHashSet<>();
        addResources(out, authorizationRequestParams(context));
        addResources(out, grantParams(context));
        return new ArrayList<>(out);
    }

    private static Map<String, Object> authorizationRequestParams(final JwtEncodingContext context) {
        final OAuth2Authorization authorization = context.getAuthorization();
        if (authorization == null) {
            return Map.of();
        }
        final OAuth2AuthorizationRequest request =
                authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        return request != null ? request.getAdditionalParameters() : Map.of();
    }

    private static Map<String, Object> grantParams(final JwtEncodingContext context) {
        final Object grant = context.getAuthorizationGrant();
        if (grant instanceof OAuth2AuthorizationGrantAuthenticationToken token) {
            final Map<String, Object> params = token.getAdditionalParameters();
            return params != null ? params : Map.of();
        }
        return Map.of();
    }

    /** A {@code resource} additional-parameter may be a single String or a collection of Strings. */
    @SuppressWarnings("unchecked")
    private static void addResources(final Set<String> out, final Map<String, Object> params) {
        final Object value = params.get(RESOURCE_PARAM);
        if (value == null) {
            return;
        }
        if (value instanceof String s) {
            if (!s.isBlank()) {
                out.add(s);
            }
        } else if (value instanceof Collection<?> c) {
            for (final Object o : c) {
                if (o instanceof String s && !s.isBlank()) {
                    out.add(s);
                }
            }
        }
    }

    private static Collection<String> resolveAllowList(final JwtEncodingContext context,
                                                       final ResourceIndicatorPublisher resourcePublisher) {
        final String clientId = clientId(context);
        if (clientId == null || clientId.isBlank() || resourcePublisher == null) {
            return List.of();
        }
        try {
            final List<String> allowed = resourcePublisher.allowedResourcesForClient(
                    group.mfnr.authorization.support.RealmScopedKey.pack(
                            group.mfnr.authorization.security.realm.RealmContextHolder.get(), clientId));
            return allowed != null ? allowed : List.of();
        } catch (final Exception e) {
            LOG.warn("Allowed-resource lookup failed for client {}, treating as no allow-list: {}",
                    clientId, e.getMessage());
            return List.of();
        }
    }

    private static String clientId(final JwtEncodingContext context) {
        return context.getRegisteredClient() != null ? context.getRegisteredClient().getClientId() : null;
    }
}
