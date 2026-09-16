package group.mfnr.authorization.security.cors;

import group.mfnr.authorization.amqp.ServiceProviderPublisher;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Helix IAM (CORS): per-client web-origin enforcement for the OAuth/OIDC endpoints. A browser request is
 * allowed cross-origin only when its {@code Origin} appears in some client's configured web origins
 * <em>for the realm it is hitting</em> (resolved from {@link RealmContextHolder}, set by the realm
 * routing filter). Replaces the starter's static, config-property allowlist so each realm's SPAs are
 * scoped to exactly the origins their clients declare.
 *
 * <p>The matched origin is reflected back (never {@code *}) so credentialed requests are valid. The
 * realm→origins lookup is fetched over AMQP and cached for a short TTL to keep preflights cheap.
 */
@Component("helixClientCors")
public class RealmClientCorsConfigurationSource implements CorsConfigurationSource {

    private static final Logger LOG = LogManager.getLogger(RealmClientCorsConfigurationSource.class);
    private static final List<String> METHODS = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD");
    private static final long TTL_MILLIS = 30_000L;

    private final ServiceProviderPublisher serviceProviderPublisher;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    public RealmClientCorsConfigurationSource(final ServiceProviderPublisher serviceProviderPublisher) {
        this.serviceProviderPublisher = serviceProviderPublisher;
    }

    @Override
    public CorsConfiguration getCorsConfiguration(final HttpServletRequest request) {
        final String origin = request.getHeader(HttpHeaders.ORIGIN);
        if (origin == null || origin.isBlank()) {
            return null;
        }
        final String realm = RealmContextHolder.get();
        if (realm == null || realm.isBlank()) {
            return null;
        }
        return corsConfigFor(origin, allowedOrigins(realm));
    }

    /**
     * Builds the CORS response for {@code origin} against the realm's {@code allowed} origins, or {@code null}
     * when the origin is not allowed (the browser then blocks the cross-origin call). A {@code *} entry
     * allows any origin (reflected). Package-visible and pure for testing.
     */
    static CorsConfiguration corsConfigFor(final String origin, final Set<String> allowed) {
        if (origin == null || origin.isBlank()) {
            return null;
        }
        if (!allowed.contains(origin) && !allowed.contains("*")) {
            return null;
        }
        final CorsConfiguration cfg = new CorsConfiguration();
        cfg.addAllowedOrigin(origin); // reflect the specific origin — valid alongside allowCredentials
        cfg.setAllowedMethods(METHODS);
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);
        return cfg;
    }

    private Set<String> allowedOrigins(final String realm) {
        final Cached hit = cache.get(realm);
        final long now = System.currentTimeMillis();
        if (hit != null && now < hit.expiry) {
            return hit.origins;
        }
        Set<String> origins = Set.of();
        try {
            origins = Set.copyOf(serviceProviderPublisher.retrieveWebOrigins(realm));
        } catch (final RuntimeException e) {
            LOG.warn("Could not load web origins for realm {}, denying cross-origin: {}", realm, e.getMessage());
        }
        cache.put(realm, new Cached(origins, now + TTL_MILLIS));
        return origins;
    }

    private record Cached(Set<String> origins, long expiry) {
    }
}
