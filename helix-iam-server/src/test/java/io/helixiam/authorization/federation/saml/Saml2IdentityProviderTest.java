package io.helixiam.authorization.federation.saml;

import io.helixiam.authorization.federation.UpstreamLogoutClient;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider.AuthnRequestContext;
import io.helixiam.authorization.federation.spi.IdentityProvider.CallbackContext;
import io.helixiam.authorization.federation.spi.IdentityProvider.LogoutContext;
import io.helixiam.authorization.federation.spi.IdentityProvider.RedirectResponse;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicReference;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E5.2: the SAML2 SP broker — builds the HTTP-Redirect AuthnRequest (deflated SAMLRequest +
 * RelayState) and, on the ACS callback, validates the Response (behind a seam) and maps the assertion
 * to a BrokeredIdentity. Rejects a RelayState mismatch (CSRF). Signature/XML validation is the seam's job.
 */
class Saml2IdentityProviderTest {

    private static final SamlProviderConfig CONFIG = new SamlProviderConfig(
            "corp-saml", "Corp SAML", "https://idp.corp/sso", "https://idp.corp/entity",
            "https://helix.test/saml/sp", "https://helix.test/broker/corp-saml/acs",
            "-----BEGIN CERTIFICATE-----...", "mail", "givenName", "sn");

    private Saml2IdentityProvider provider(final SamlAssertionValidator validator) {
        return new Saml2IdentityProvider(CONFIG, validator, () -> "_id-1", () -> "2026-06-25T00:00:00Z");
    }

    @Test
    void metadata_isSaml2() {
        assertThat(provider((c, r, s) -> null).metadata().protocol()).isEqualTo(IdpMetadata.Protocol.SAML2);
    }

    @Test
    void start_buildsTheRedirectWithADeflatedAuthnRequestAndRelayState() throws Exception {
        final RedirectResponse redirect = provider((c, r, s) -> null)
                .start(new AuthnRequestContext("master", "state-abc", CONFIG.assertionConsumerServiceUrl()));

        assertThat(redirect.location()).startsWith("https://idp.corp/sso?")
                .contains("SAMLRequest=").contains("RelayState=state-abc");

        // the SAMLRequest must inflate to an AuthnRequest carrying our SP issuer + the IdP destination
        final String samlRequestParam = paramValue(redirect.location(), "SAMLRequest");
        final String xml = inflate(URLDecoder.decode(samlRequestParam, StandardCharsets.UTF_8));
        assertThat(xml).contains("AuthnRequest").contains(CONFIG.spEntityId()).contains(CONFIG.ssoUrl());
    }

    @Test
    void callback_validatesTheResponseAndMapsTheAssertionToABrokeredIdentity() {
        final SamlAssertionValidator validator = (cfg, resp, relay) -> new SamlAssertionValidator.ValidatedAssertion(
                "ada@corp", Map.of("mail", "ada@corp", "givenName", "Ada", "sn", "Lovelace"));
        final CallbackContext ctx = new CallbackContext("master",
                Map.of("SAMLResponse", "base64resp", "RelayState", "state-abc"), "state-abc", null, CONFIG.assertionConsumerServiceUrl());

        final BrokeredIdentity identity = provider(validator).callback(ctx);

        assertThat(identity.idpAlias()).isEqualTo("corp-saml");
        assertThat(identity.externalSubject()).isEqualTo("ada@corp");
        assertThat(identity.email()).isEqualTo("ada@corp");
        assertThat(identity.emailVerified()).isTrue(); // IdP-asserted
        assertThat(identity.attributes()).containsEntry("firstName", "Ada").containsEntry("lastName", "Lovelace");
    }

    @Test
    void callback_rejectsARelayStateMismatch_csrf() {
        final CallbackContext ctx = new CallbackContext("master",
                Map.of("SAMLResponse", "base64resp", "RelayState", "attacker"), "state-abc", null, CONFIG.assertionConsumerServiceUrl());

        assertThatThrownBy(() -> provider((c, r, s) -> null).callback(ctx)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void logout_deliversALogoutRequestToTheUpstreamSloEndpoint() throws Exception {
        final SamlProviderConfig withSlo = new SamlProviderConfig(
                "corp-saml", "Corp SAML", "https://idp.corp/sso", "https://idp.corp/entity",
                "https://helix.test/saml/sp", "https://helix.test/broker/corp-saml/acs",
                "-----BEGIN CERTIFICATE-----...", "mail", "givenName", "sn", "https://idp.corp/slo");
        final AtomicReference<String> got = new AtomicReference<>();
        final UpstreamLogoutClient capture = got::set;
        final Saml2IdentityProvider provider = new Saml2IdentityProvider(
                withSlo, (c, r, s) -> null, () -> "_lr-1", () -> "2026-06-25T00:00:00Z", capture);

        provider.logout(new LogoutContext("master", "user-1", "corp-saml", null, "ada@corp", "sess-9"));

        assertThat(got.get()).startsWith("https://idp.corp/slo?").contains("SAMLRequest=");
        final String xml = inflate(URLDecoder.decode(paramValue(got.get(), "SAMLRequest"), StandardCharsets.UTF_8));
        assertThat(xml).contains("LogoutRequest").contains("ada@corp").contains("sess-9").contains(withSlo.spEntityId());
    }

    @Test
    void logout_isANoOpWhenNoSloEndpointConfigured() {
        final AtomicReference<String> got = new AtomicReference<>();
        final Saml2IdentityProvider provider = new Saml2IdentityProvider(
                CONFIG, (c, r, s) -> null, () -> "_lr-1", () -> "2026-06-25T00:00:00Z", got::set);
        provider.logout(new LogoutContext("master", "user-1", "corp-saml", null, "ada@corp", "sess-9"));
        assertThat(got.get()).isNull(); // CONFIG has no SLO URL → nothing sent upstream
    }

    private static String paramValue(final String url, final String name) {
        for (final String pair : url.substring(url.indexOf('?') + 1).split("&")) {
            final int eq = pair.indexOf('=');
            if (pair.substring(0, eq).equals(name)) {
                return pair.substring(eq + 1);
            }
        }
        throw new IllegalArgumentException("no param " + name);
    }

    private static String inflate(final String base64Deflated) throws Exception {
        final byte[] compressed = Base64.getDecoder().decode(base64Deflated);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (final InflaterOutputStream ios = new InflaterOutputStream(out, new Inflater(true))) {
            ios.write(compressed);
        }
        return out.toString(StandardCharsets.UTF_8);
    }
}
