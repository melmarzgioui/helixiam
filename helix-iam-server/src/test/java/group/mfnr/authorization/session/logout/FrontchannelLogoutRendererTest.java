package group.mfnr.authorization.session.logout;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Helix IAM SSO P6: the OIDC Front-Channel Logout interstitial — one iframe per client (each pointed at its
 * {@code frontchannel_logout_uri} carrying {@code iss}+{@code sid}), then a redirect to the post-logout URI.
 */
class FrontchannelLogoutRendererTest {

    private final FrontchannelLogoutRenderer renderer = new FrontchannelLogoutRenderer();

    @Test
    void render_oneIframePerClient_withIssAndSid_andRedirect() {
        final String html = renderer.render("https://idp/realms/master", "sid-1", List.of(
                new LogoutTargetResolver.FrontchannelTarget("a", "https://a/fc"),
                new LogoutTargetResolver.FrontchannelTarget("b", "https://b/fc?x=1")),
                "https://app/after-logout");

        assertTrue(html.contains("<iframe"), "must embed iframes");
        // Inside the HTML attribute the '&' between query params is correctly escaped to '&amp;'.
        assertTrue(html.contains("https://a/fc?iss=https%3A%2F%2Fidp%2Frealms%2Fmaster&amp;sid=sid-1"));
        assertTrue(html.contains("https://b/fc?x=1&amp;iss=https%3A%2F%2Fidp%2Frealms%2Fmaster&amp;sid=sid-1"),
                "an existing query string must be preserved with &");
        assertTrue(html.contains("https://app/after-logout"), "must redirect to the post-logout URI");
    }

    @Test
    void render_escapesHtmlMetacharacters_inUris() {
        final String html = renderer.render("https://idp", "s", List.of(
                new LogoutTargetResolver.FrontchannelTarget("evil", "https://e/fc\"><script>alert(1)</script>")), "/");

        assertFalse(html.contains("<script>alert(1)</script>"), "the iframe src must be HTML-escaped");
    }
}
