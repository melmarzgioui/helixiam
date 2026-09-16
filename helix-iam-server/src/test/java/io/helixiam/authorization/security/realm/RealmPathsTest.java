package io.helixiam.authorization.security.realm;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM: the flow-engine challenge loop ({@code FlowController}) and the legacy MFA controller
 * issue server-side redirects and render form actions back to their own endpoints. Under realm-path
 * routing ({@code /realms/{realm}/...}) those must carry the realm prefix, or the browser posts to the
 * flat path and the realm-routing guard 404s. {@link RealmPaths} centralises that prefixing.
 */
class RealmPathsTest {

    @Test
    void prefixesPathWithTheRealm() {
        assertThat(RealmPaths.prefixed("master", "/flow")).isEqualTo("/realms/master/flow");
        assertThat(RealmPaths.prefixed("acme", "/login")).isEqualTo("/realms/acme/login");
    }

    @Test
    void fallsBackToTheBarePathWhenRealmIsAbsent() {
        // No realm in context (flat access): keep the path as-is rather than emitting /realms//flow.
        assertThat(RealmPaths.prefixed(null, "/flow")).isEqualTo("/flow");
        assertThat(RealmPaths.prefixed("", "/flow")).isEqualTo("/flow");
        assertThat(RealmPaths.prefixed("  ", "/flow")).isEqualTo("/flow");
    }

    @Test
    void normalisesAMissingLeadingSlash() {
        assertThat(RealmPaths.prefixed("master", "flow")).isEqualTo("/realms/master/flow");
    }
}
