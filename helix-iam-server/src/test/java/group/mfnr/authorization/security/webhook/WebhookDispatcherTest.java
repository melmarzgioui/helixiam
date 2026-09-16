package group.mfnr.authorization.security.webhook;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Helix IAM B6: event-type filtering + HMAC signing for outbound webhooks. */
class WebhookDispatcherTest {

    @Test
    void matches_blankFilter_matchesEverything() {
        assertThat(WebhookDispatcher.matches(null, "LOGIN_SUCCESS", "AUTHN")).isTrue();
        assertThat(WebhookDispatcher.matches("", "ADMIN_POST", "ADMIN")).isTrue();
    }

    @Test
    void matches_byType_orByCategory_caseInsensitive() {
        assertThat(WebhookDispatcher.matches("LOGIN_SUCCESS,LOGIN_FAILURE", "login_success", "AUTHN")).isTrue();
        assertThat(WebhookDispatcher.matches("ADMIN", "ADMIN_POST", "ADMIN")).isTrue(); // category match
        assertThat(WebhookDispatcher.matches("LOGIN_SUCCESS", "LOGIN_FAILURE", "AUTHN")).isFalse();
    }

    @Test
    void sign_isStableHmacSha256Hex_andEmptyWithoutSecret() {
        final String a = WebhookDispatcher.sign("shh", "{\"x\":1}");
        final String b = WebhookDispatcher.sign("shh", "{\"x\":1}");
        assertThat(a).isEqualTo(b).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(WebhookDispatcher.sign("other", "{\"x\":1}")).isNotEqualTo(a);
        assertThat(WebhookDispatcher.sign(null, "{\"x\":1}")).isEmpty();
    }
}
