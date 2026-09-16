package io.helixiam.authorization.session.logout;

import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Helix IAM SSO P6: renders the OIDC Front-Channel Logout interstitial. The browser loads one hidden iframe
 * per participating client (each pointed at its {@code frontchannel_logout_uri} with the {@code iss}+{@code sid}
 * query params per the spec, so the RP can clear its own session), then is redirected to the post-logout URI.
 * All URLs are HTML-escaped to keep the page injection-safe.
 */
@Component
public class FrontchannelLogoutRenderer {

    /** Full HTML document for the front-channel logout page. */
    public String render(final String issuer, final String sid,
                         final List<LogoutTargetResolver.FrontchannelTarget> targets, final String postLogoutRedirectUri) {
        final String redirect = postLogoutRedirectUri == null || postLogoutRedirectUri.isBlank()
                ? "/" : postLogoutRedirectUri;
        final StringBuilder iframes = new StringBuilder();
        if (targets != null) {
            for (final LogoutTargetResolver.FrontchannelTarget target : targets) {
                if (target.frontchannelLogoutUri() == null || target.frontchannelLogoutUri().isBlank()) {
                    continue;
                }
                iframes.append("  <iframe src=\"").append(htmlEscape(withIssSid(target.frontchannelLogoutUri(), issuer, sid)))
                        .append("\" style=\"display:none\" aria-hidden=\"true\"></iframe>\n");
            }
        }
        return "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<title>Signing out…</title>"
                + "<meta http-equiv=\"refresh\" content=\"2;url=" + htmlEscape(redirect) + "\">"
                + "</head><body>\n"
                + "<p>Signing you out of all applications…</p>\n"
                + iframes
                + "<script>setTimeout(function(){location.href=" + jsString(redirect) + ";},2000);</script>\n"
                + "</body></html>\n";
    }

    /** Append the OIDC {@code iss}+{@code sid} query params (preserving any existing query string). */
    private static String withIssSid(final String uri, final String issuer, final String sid) {
        final String sep = uri.contains("?") ? "&" : "?";
        final StringBuilder out = new StringBuilder(uri);
        if (issuer != null) {
            out.append(sep).append("iss=").append(URLEncoder.encode(issuer, StandardCharsets.UTF_8));
            if (sid != null && !sid.isBlank()) {
                out.append("&sid=").append(URLEncoder.encode(sid, StandardCharsets.UTF_8));
            }
        } else if (sid != null && !sid.isBlank()) {
            out.append(sep).append("sid=").append(URLEncoder.encode(sid, StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    private static String htmlEscape(final String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static String jsString(final String value) {
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'").replace("<", "\\u003c") + "'";
    }
}
