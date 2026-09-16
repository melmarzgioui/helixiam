package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.realm.RealmAdminPublisher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Helix IAM E8.5: the OIDC/OAuth2 endpoint URLs a relying party integrates against — surfaced per realm
 * (the "Endpoints" view on Realm settings). Values mirror the realm's discovery document
 * ({@code /realms/{realm}/.well-known/openid-configuration}). The issuer is the realm-prefixed
 * {@code {base}/realms/{realm}}, where {@code base} is the realm's configured Issuer URL
 * ({@code RealmConfig.issuer}) when set, else the server's {@code AuthorizationServerSettings} issuer,
 * else (dev) the request host.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/endpoints")
public class OidcEndpointsController {

    private static final Logger LOG = LogManager.getLogger(OidcEndpointsController.class);

    private final AuthorizationServerSettings settings;
    private final RealmAdminPublisher realmAdminPublisher;

    public OidcEndpointsController(final AuthorizationServerSettings settings,
                                   final RealmAdminPublisher realmAdminPublisher) {
        this.settings = settings;
        this.realmAdminPublisher = realmAdminPublisher;
    }

    @GetMapping
    public OidcEndpoints get(@PathVariable final String realmId) {
        final String issuer = resolveIssuer(realmId);
        return new OidcEndpoints(
                issuer,
                issuer + "/.well-known/openid-configuration",
                issuer + settings.getAuthorizationEndpoint(),
                issuer + settings.getTokenEndpoint(),
                issuer + settings.getDeviceAuthorizationEndpoint(),
                issuer + settings.getOidcUserInfoEndpoint(),
                issuer + settings.getJwkSetEndpoint(),
                issuer + settings.getOidcLogoutEndpoint(),
                issuer + settings.getTokenIntrospectionEndpoint(),
                issuer + settings.getTokenRevocationEndpoint());
    }

    /**
     * The realm-prefixed issuer {@code {base}/realms/{realm}} (MT-3) — matching the discovery document
     * SAS serves under the realm path. {@code base} is the realm Issuer URL (if configured) → server-wide
     * issuer → request base. If the configured value already ends with {@code /realms/{realm}} it is used
     * as-is (no double prefix).
     */
    private String resolveIssuer(final String realmId) {
        final String base = resolveIssuerBase(realmId);
        final String suffix = "/realms/" + realmId;
        return base.endsWith(suffix) ? base : base + suffix;
    }

    /** Realm Issuer URL (if configured) → server-wide issuer → request base. Trailing slash stripped. */
    private String resolveIssuerBase(final String realmId) {
        try {
            final var realm = realmAdminPublisher.get(realmId);
            if (realm != null && realm.issuer() != null && !realm.issuer().isBlank()) {
                return trimSlash(realm.issuer().trim());
            }
        } catch (final Exception e) {
            LOG.warn("Could not read realm {} issuer, falling back to server issuer/request host: {}", realmId, e.getMessage());
        }
        if (settings.getIssuer() != null) {
            return trimSlash(settings.getIssuer());
        }
        return trimSlash(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString());
    }

    private static String trimSlash(final String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** The integration URLs for a realm's OIDC/OAuth2 endpoints. */
    public record OidcEndpoints(String issuer, String discovery, String authorization, String token,
                                String deviceAuthorization, String userInfo, String jwks, String endSession,
                                String introspection, String revocation) {
    }
}
