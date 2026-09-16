package group.mfnr.authorization.federation.saml;

import group.mfnr.authorization.federation.UpstreamLogoutClient;
import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import group.mfnr.authorization.federation.spi.IdentityProvider;
import group.mfnr.authorization.federation.spi.IdpMetadata;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * Helix IAM E5.2: the SAML2 federation broker (Service Provider role, HTTP-Redirect AuthnRequest +
 * HTTP-POST ACS). {@link #start} builds the deflated, base64'd SAMLRequest redirect with the realm's
 * anti-forgery state as RelayState; {@link #callback} verifies the returned RelayState (CSRF), then
 * delegates Response signature/XML/condition validation to {@link SamlAssertionValidator} and maps
 * the validated assertion to a {@link BrokeredIdentity}. The validator is OpenSAML-backed in prod.
 */
public class Saml2IdentityProvider implements IdentityProvider {

    private final SamlProviderConfig config;
    private final SamlAssertionValidator validator;
    private final Supplier<String> idGenerator;
    private final Supplier<String> instantSupplier;
    private final UpstreamLogoutClient upstreamLogoutClient;

    public Saml2IdentityProvider(final SamlProviderConfig config, final SamlAssertionValidator validator,
                                 final Supplier<String> idGenerator, final Supplier<String> instantSupplier) {
        this(config, validator, idGenerator, instantSupplier, new UpstreamLogoutClient.Http());
    }

    public Saml2IdentityProvider(final SamlProviderConfig config, final SamlAssertionValidator validator,
                                 final Supplier<String> idGenerator, final Supplier<String> instantSupplier,
                                 final UpstreamLogoutClient upstreamLogoutClient) {
        this.config = config;
        this.validator = validator;
        this.idGenerator = idGenerator;
        this.instantSupplier = instantSupplier;
        this.upstreamLogoutClient = upstreamLogoutClient;
    }

    @Override
    public IdpMetadata metadata() {
        return IdpMetadata.of(config.alias(), IdpMetadata.Protocol.SAML2, config.displayName());
    }

    @Override
    public RedirectResponse start(final AuthnRequestContext context) {
        final String authnRequest = ""
                + "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                + " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
                + " ID=\"" + escape(idGenerator.get()) + "\" Version=\"2.0\""
                + " IssueInstant=\"" + escape(instantSupplier.get()) + "\""
                + " Destination=\"" + escape(config.ssoUrl()) + "\""
                + " AssertionConsumerServiceURL=\"" + escape(config.assertionConsumerServiceUrl()) + "\""
                + " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">"
                + "<saml:Issuer>" + escape(config.spEntityId()) + "</saml:Issuer>"
                + "</samlp:AuthnRequest>";

        final String samlRequest = enc(deflateBase64(authnRequest));
        final String location = config.ssoUrl() + "?SAMLRequest=" + samlRequest
                + "&RelayState=" + enc(context.state());
        return new RedirectResponse(location, Map.of("RelayState", context.state()));
    }

    @Override
    public BrokeredIdentity callback(final CallbackContext context) {
        final Map<String, String> params = context.parameters();
        final String relayState = params.get("RelayState");
        if (context.expectedState() == null || !context.expectedState().equals(relayState)) {
            throw new IllegalStateException("SAML RelayState mismatch (possible CSRF) for provider " + config.alias());
        }
        final String samlResponse = params.get("SAMLResponse");
        if (samlResponse == null || samlResponse.isBlank()) {
            throw new IllegalArgumentException("SAML callback missing SAMLResponse for provider " + config.alias());
        }

        final SamlAssertionValidator.ValidatedAssertion assertion =
                validator.validate(config, samlResponse, context.expectedState());

        final Map<String, String> attrs = assertion.attributes() == null ? Map.of() : assertion.attributes();
        final Map<String, String> mapped = new HashMap<>();
        putIfPresent(mapped, "firstName", attrs.get(config.firstNameAttribute()));
        putIfPresent(mapped, "lastName", attrs.get(config.lastNameAttribute()));
        final String email = attrs.get(config.emailAttribute());

        // The IdP asserted the identity, so the email is treated as verified.
        return new BrokeredIdentity(config.alias(), assertion.nameId(), email, true, mapped);
    }

    @Override
    public void logout(final LogoutContext context) {
        // SSO P9: SP-initiated federated logout — deliver a signed-by-binding LogoutRequest to the upstream
        // IdP's SLO endpoint over HTTP-Redirect, best-effort (a failure must never block the local logout).
        // The generic SAML broker config carries no SP key, so the LogoutRequest is unsigned (the Issuer +
        // NameID identify the SP); eID — which has an SP signing key — signs its LogoutRequest.
        final String slo = config.singleLogoutServiceUrl();
        if (slo == null || slo.isBlank() || context.upstreamNameId() == null || context.upstreamNameId().isBlank()) {
            return; // no SLO endpoint configured, or no upstream NameID captured at login
        }
        final String sessionIndexXml = context.upstreamSessionIndex() == null || context.upstreamSessionIndex().isBlank()
                ? "" : "<samlp:SessionIndex>" + escape(context.upstreamSessionIndex()) + "</samlp:SessionIndex>";
        final String logoutRequest = ""
                + "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                + " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
                + " ID=\"" + escape(idGenerator.get()) + "\" Version=\"2.0\""
                + " IssueInstant=\"" + escape(instantSupplier.get()) + "\""
                + " Destination=\"" + escape(slo) + "\">"
                + "<saml:Issuer>" + escape(config.spEntityId()) + "</saml:Issuer>"
                + "<saml:NameID>" + escape(context.upstreamNameId()) + "</saml:NameID>"
                + sessionIndexXml
                + "</samlp:LogoutRequest>";
        final String url = slo + (slo.contains("?") ? "&" : "?") + "SAMLRequest=" + enc(deflateBase64(logoutRequest))
                + "&RelayState=" + enc(context.realmId() == null ? "" : context.realmId());
        try {
            upstreamLogoutClient.get(url);
        } catch (final RuntimeException e) {
            // upstream IdP unreachable / rejected the logout — the local session is already gone.
        }
    }

    /** DEFLATE (raw, no zlib header) + base64 — the SAML HTTP-Redirect binding encoding. */
    private static String deflateBase64(final String xml) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try (final DeflaterOutputStream dos = new DeflaterOutputStream(out, deflater)) {
            dos.write(xml.getBytes(StandardCharsets.UTF_8));
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to encode SAML AuthnRequest", e);
        } finally {
            deflater.end();
        }
        return java.util.Base64.getEncoder().encodeToString(out.toByteArray());
    }

    private static void putIfPresent(final Map<String, String> map, final String key, final String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }

    private static String enc(final String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    private static String escape(final String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
