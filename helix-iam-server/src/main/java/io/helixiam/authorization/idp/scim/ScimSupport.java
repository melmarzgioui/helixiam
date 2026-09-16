package io.helixiam.authorization.idp.scim;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Helix IAM E7 (SCIM 2.0): request-scoped helpers — the realm-prefixed SCIM base URL (for {@code
 * meta.location}) and the {@code Authorization: Bearer} token. The {@link
 * io.helixiam.authorization.security.realm.RealmRoutingFilter} strips {@code /realms/{realm}} from the
 * servlet path and exposes the realm via the request context-path, so the SCIM base is the full request
 * context-path + {@code /scim/v2}.
 */
public final class ScimSupport {

    private static final String BEARER = "Bearer ";

    private ScimSupport() {
    }

    /** The {@code Authorization: Bearer} token, or {@code null} when absent / malformed. */
    public static String bearerToken(final HttpServletRequest request) {
        final String header = request.getHeader("Authorization");
        if (header == null || !header.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return null;
        }
        final String token = header.substring(BEARER.length()).trim();
        return token.isEmpty() ? null : token;
    }

    /** The realm-prefixed SCIM v2 base URL ({@code {ctx}/scim/v2}) for building {@code meta.location}. */
    public static String baseUrl() {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/scim/v2").build().toUriString();
    }
}
