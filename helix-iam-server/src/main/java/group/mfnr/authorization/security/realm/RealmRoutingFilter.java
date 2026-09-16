package group.mfnr.authorization.security.realm;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helix IAM (multi-tenant): makes the auth server serve every realm under {@code /realms/{realm}/…}
 *. Runs <b>before</b> Spring Security and treats {@code /realms/{realm}} as a dynamic
 * servlet context-path extension: the wrapped request reports a context path of {@code …/realms/{realm}}
 * and a stripped servlet path ({@code /oauth2/token}, {@code /login}, {@code /broker/…}). So the existing
 * <b>flat</b> security rules + controller mappings + the Spring Authorization Server match unchanged, while
 * every outbound URL (redirects, links, discovery, issuer) comes out realm-prefixed. The realm is exposed
 * via {@link RealmContextHolder} for the login flow / client lookup / key source.
 *
 * <p>Realm-prefixed-only: non-realm protocol paths 404. {@code /admin/**}, actuator and error bypass.
 */
public class RealmRoutingFilter extends OncePerRequestFilter {

    private static final Pattern REALM = Pattern.compile("^/realms/([^/]+)(/.*)?$");

    /** Optional realm-existence oracle; when set, an unknown realm 404s instead of serving a synthesized doc. */
    private final RealmSettingsResolver realms;

    public RealmRoutingFilter() {
        this(null);
    }

    public RealmRoutingFilter(final RealmSettingsResolver realms) {
        this.realms = realms;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final String ctx = request.getContextPath();
        final String path = request.getRequestURI().substring(ctx.length());

        // Infrastructure that is realm-agnostic: the admin/console API, actuator, error dispatch, and
        // the static login-page assets (CSS/JS/images/fonts/webjars) — these are shared across realms and
        // the login templates reference them at flat paths, so they must be reachable without a realm prefix.
        if (path.startsWith("/admin") || path.startsWith("/actuator") || path.equals("/error")
                || path.startsWith("/css") || path.startsWith("/js") || path.startsWith("/img")
                || path.startsWith("/webjars") || path.startsWith("/assets") || path.startsWith("/fonts")
                || path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui")
                || path.equals("/favicon.ico")) {
            chain.doFilter(request, response);
            return;
        }

        final Matcher m = REALM.matcher(path);
        if (!m.matches()) {
            // Realm-prefixed-only: a flat protocol path (e.g. /oauth2/token, /.well-known/…) is not served.
            // setStatus (not sendError) so we return a clean 404 here instead of dispatching to /error,
            // which Spring Security would turn into a 302 login redirect.
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("Not found. Endpoints are served under /realms/{realm}/.");
            return;
        }
        final String realm = m.group(1);
        final String rest = (m.group(2) == null || m.group(2).isEmpty()) ? "/" : m.group(2);

        // Reject requests for a realm that doesn't exist (Keycloak parity) — otherwise SAS templates the
        // issuer from the path and happily serves a synthesized discovery doc for any bogus realm. Fails
        // OPEN (see RealmSettingsResolver.exists) so a lookup hiccup never 404s a valid realm. setStatus
        // (not sendError) to avoid the /error → 302-login dispatch.
        if (realms != null && !realms.exists(realm)) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("Realm '" + realm + "' does not exist.");
            return;
        }

        RealmContextHolder.set(realm);
        request.setAttribute(RealmContextHolder.ATTRIBUTE, realm);
        try {
            chain.doFilter(new VirtualContextRequest(request, ctx + "/realms/" + realm, rest), response);
        } finally {
            RealmContextHolder.clear();
        }
    }

    /**
     * Reports {@code /realms/{realm}} as part of the context path so Spring resolves the app-relative path
     * (e.g. {@code /oauth2/token}) for matching, and builds context-relative outbound URLs under the realm.
     * {@code getRequestURI()} is left untouched (it already carries the realm prefix).
     */
    private static final class VirtualContextRequest extends HttpServletRequestWrapper {
        private final String contextPath;
        private final String servletPath;

        VirtualContextRequest(final HttpServletRequest request, final String contextPath, final String servletPath) {
            super(request);
            this.contextPath = contextPath;
            this.servletPath = servletPath;
        }

        @Override
        public String getContextPath() {
            return contextPath;
        }

        @Override
        public String getServletPath() {
            return servletPath;
        }

        @Override
        public String getPathInfo() {
            return null;
        }
    }
}
