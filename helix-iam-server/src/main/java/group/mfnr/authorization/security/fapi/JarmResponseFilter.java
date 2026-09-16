package group.mfnr.authorization.security.fapi;

import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM B11 (FAPI / JARM — JWT Secured Authorization Response Mode): when the client opts into a
 * {@code .jwt} response mode, repackage the authorization endpoint's success/error redirect parameters
 * (code/state/iss or error/...) into a single signed {@code response} JWT, delivered via the underlying
 * base mode (query/fragment). Implemented by wrapping {@code sendRedirect} and transforming ONLY a redirect
 * to one of the client's registered redirect URIs — every other redirect (login, consent) passes through
 * untouched, so the default OAuth flow is byte-identical for non-JARM clients.
 */
public class JarmResponseFilter extends OncePerRequestFilter {

    private static final Logger LOG = LogManager.getLogger(JarmResponseFilter.class);
    private static final long TTL_SECONDS = 120;

    private final RegisteredClientRepository clients;
    private final JwtEncoder jwtEncoder;

    public JarmResponseFilter(final RegisteredClientRepository clients, final JwtEncoder jwtEncoder) {
        this.clients = clients;
        this.jwtEncoder = jwtEncoder;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final RegisteredClient client = resolveClient(request);
        final String mode = client == null ? null
                : (String) client.getClientSettings().getSetting("helix.jarm.response_mode");
        if (!JarmResponse.isJarm(mode)) {
            chain.doFilter(request, response);
            return;
        }
        final String issuer = issuerFrom(request);
        final String baseMode = JarmResponse.baseMode(mode);
        chain.doFilter(request, new JarmRedirectResponse(response, client, issuer, baseMode));
    }

    private RegisteredClient resolveClient(final HttpServletRequest request) {
        final String clientId = request.getParameter("client_id");
        if (clientId == null || clientId.isBlank()) {
            return null;
        }
        try {
            return clients.findByClientId(clientId);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    /** The realm issuer = the request URL with the {@code /oauth2/authorize} suffix removed. */
    private static String issuerFrom(final HttpServletRequest request) {
        final String url = request.getRequestURL().toString();
        final int idx = url.indexOf("/oauth2/authorize");
        return idx > 0 ? url.substring(0, idx) : url;
    }

    /** Wraps the response so only an authorization redirect to a registered redirect URI is rewritten as JARM. */
    private final class JarmRedirectResponse extends HttpServletResponseWrapper {
        private final RegisteredClient client;
        private final String issuer;
        private final String baseMode;

        JarmRedirectResponse(final HttpServletResponse delegate, final RegisteredClient client,
                             final String issuer, final String baseMode) {
            super(delegate);
            this.client = client;
            this.issuer = issuer;
            this.baseMode = baseMode;
        }

        @Override
        public void sendRedirect(final String location) throws IOException {
            final String transformed = transform(location);
            super.sendRedirect(transformed != null ? transformed : location);
        }

        /** Returns a JARM-wrapped redirect when {@code location} is an authorization response to a registered URI; else null. */
        private String transform(final String location) {
            try {
                if (location == null) {
                    return null;
                }
                final boolean toRegistered = client.getRedirectUris().stream().anyMatch(location::startsWith);
                if (!toRegistered) {
                    return null; // login/consent/other redirect — leave untouched
                }
                final URI uri = URI.create(location);
                final Map<String, String> params = new LinkedHashMap<>();
                parseInto(uri.getRawQuery(), params);
                parseInto(uri.getRawFragment(), params);
                // Only an actual authorization response carries code or error.
                if (!params.containsKey("code") && !params.containsKey("error")) {
                    return null;
                }
                final JWTClaimsSet claims = JarmResponse.claims(issuer, client.getClientId(), params,
                        Instant.now(), TTL_SECONDS);
                final String responseJwt = sign(claims);
                final String base = location.substring(0, location.length()
                        - (uri.getRawQuery() != null ? uri.getRawQuery().length() + 1 : 0)
                        - (uri.getRawFragment() != null ? uri.getRawFragment().length() + 1 : 0));
                final String sep = "fragment".equals(baseMode) ? "#" : "?";
                return base + sep + "response=" + java.net.URLEncoder.encode(responseJwt, StandardCharsets.UTF_8);
            } catch (final Exception e) {
                LOG.warn("JARM response packaging failed for client {}, sending the plain response: {}",
                        client.getClientId(), e.getMessage());
                return null;
            }
        }

        private String sign(final JWTClaimsSet claims) {
            final JwtClaimsSet.Builder set = JwtClaimsSet.builder()
                    .issuer(claims.getIssuer())
                    .audience(claims.getAudience())
                    .issuedAt(claims.getIssueTime().toInstant())
                    .expiresAt(claims.getExpirationTime().toInstant());
            claims.getClaims().forEach((k, v) -> {
                if (!Set.of("iss", "aud", "iat", "exp").contains(k)) {
                    set.claim(k, v);
                }
            });
            return jwtEncoder.encode(JwtEncoderParameters.from(
                    JwsHeader.with(SignatureAlgorithm.RS256).build(), set.build())).getTokenValue();
        }

        private void parseInto(final String raw, final Map<String, String> out) {
            if (raw == null || raw.isBlank()) {
                return;
            }
            for (final String pair : raw.split("&")) {
                final int eq = pair.indexOf('=');
                if (eq > 0) {
                    out.put(java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                            java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                }
            }
        }
    }
}
