package group.mfnr.authorization.federation.oidc;

import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import group.mfnr.authorization.federation.spi.IdentityProvider.AuthnRequestContext;
import group.mfnr.authorization.federation.spi.IdentityProvider.CallbackContext;
import group.mfnr.authorization.federation.spi.IdentityProvider.RedirectResponse;
import group.mfnr.authorization.federation.spi.IdpMetadata;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E5.2: the OIDC broker — builds the authorize redirect (state + nonce + scope) and, on
 * callback, exchanges the code (behind a seam) and maps the ID-token claims to a BrokeredIdentity.
 * Rejects a state mismatch (CSRF) and a nonce mismatch (replay). Network is behind OidcTokenClient.
 */
class OidcIdentityProviderTest {

    private static final OidcProviderConfig CONFIG = new OidcProviderConfig(
            "acme", "ACME SSO", "client-123", "secret",
            "https://idp.acme.test/authorize", "https://idp.acme.test/token",
            "https://idp.acme.test/jwks", "https://idp.acme.test", List.of("openid", "email", "profile"));

    private OidcIdentityProvider provider(final OidcTokenClient client) {
        return new OidcIdentityProvider(CONFIG, client, () -> "fixed-nonce");
    }

    @Test
    void metadata_isOidcWithTheConfiguredAlias() {
        final IdpMetadata meta = provider((c, code, r) -> null).metadata();
        assertThat(meta.alias()).isEqualTo("acme");
        assertThat(meta.protocol()).isEqualTo(IdpMetadata.Protocol.OIDC);
    }

    @Test
    void start_buildsTheAuthorizeRedirectWithStateNonceAndScope() {
        final RedirectResponse redirect = provider((c, code, r) -> null)
                .start(new AuthnRequestContext("master", "state-abc", "https://helix.test/broker/acme/callback"));

        assertThat(redirect.location())
                .startsWith("https://idp.acme.test/authorize?")
                .contains("response_type=code")
                .contains("client_id=client-123")
                .contains("state=state-abc")
                .contains("nonce=fixed-nonce")
                .contains("scope=openid")
                .contains("redirect_uri=https%3A%2F%2Fhelix.test%2Fbroker%2Facme%2Fcallback");
        // the generated nonce is handed back so the runtime can stash it for callback validation
        assertThat(redirect.parameters()).containsEntry("nonce", "fixed-nonce");
    }

    @Test
    void callback_exchangesTheCodeAndMapsClaimsToABrokeredIdentity() {
        final OidcTokenClient client = (cfg, code, redirectUri) -> new OidcTokenClient.OidcTokens(
                Map.of("sub", "ext-1", "email", "ada@acme.test", "email_verified", true,
                        "nonce", "fixed-nonce", "given_name", "Ada"),
                "access-xyz");
        final CallbackContext ctx = new CallbackContext("master",
                Map.of("code", "auth-code", "state", "state-abc"), "state-abc", "fixed-nonce",
                "https://helix.test/broker/acme/callback");

        final BrokeredIdentity identity = provider(client).callback(ctx);

        assertThat(identity.idpAlias()).isEqualTo("acme");
        assertThat(identity.externalSubject()).isEqualTo("ext-1");
        assertThat(identity.email()).isEqualTo("ada@acme.test");
        assertThat(identity.emailVerified()).isTrue();
        assertThat(identity.attributes()).containsEntry("given_name", "Ada");
    }

    @Test
    void callback_rejectsAStateMismatch_csrf() {
        final CallbackContext ctx = new CallbackContext("master",
                Map.of("code", "auth-code", "state", "attacker-state"), "state-abc", "fixed-nonce",
                "https://helix.test/broker/acme/callback");

        assertThatThrownBy(() -> provider((c, code, r) -> null).callback(ctx))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void callback_rejectsANonceMismatch_replay() {
        final OidcTokenClient client = (cfg, code, redirectUri) -> new OidcTokenClient.OidcTokens(
                Map.of("sub", "ext-1", "nonce", "stale-nonce"), "access-xyz");
        final CallbackContext ctx = new CallbackContext("master",
                Map.of("code", "auth-code", "state", "state-abc"), "state-abc", "fixed-nonce",
                "https://helix.test/broker/acme/callback");

        assertThatThrownBy(() -> provider(client).callback(ctx)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void callback_missingCode_throws() {
        final CallbackContext ctx = new CallbackContext("master",
                Map.of("state", "state-abc"), "state-abc", "fixed-nonce", "https://helix.test/cb");

        assertThatThrownBy(() -> provider((c, code, r) -> null).callback(ctx))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
