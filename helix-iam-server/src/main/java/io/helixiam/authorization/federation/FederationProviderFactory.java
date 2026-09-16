package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.eid.EidArtifactResolver;
import io.helixiam.authorization.federation.eid.EidAssertionValidator;
import io.helixiam.authorization.federation.eid.EidProviderConfig;
import io.helixiam.authorization.federation.eid.EidSamlIdentityProvider;
import io.helixiam.authorization.federation.oidc.OidcIdentityProvider;
import io.helixiam.authorization.federation.oidc.OidcProviderConfig;
import io.helixiam.authorization.federation.oidc.OidcTokenClient;
import io.helixiam.authorization.federation.oidc.SocialProviders;
import io.helixiam.authorization.federation.saml.Saml2IdentityProvider;
import io.helixiam.authorization.federation.saml.SamlAssertionValidator;
import io.helixiam.authorization.federation.saml.SamlProviderConfig;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM E5.4: builds runtime {@link IdentityProvider}s from {@link FederationProviderProperties}.
 * Generic OIDC and SAML2 entries map straight onto their broker; social entries resolve to a built-in
 * {@link SocialProviders} preset so the operator supplies only a client id + secret. The shared
 * back-channel collaborators (OIDC token client, SAML assertion validator) are injected beans; the
 * per-request nonce / request-id / instant suppliers are cryptographically random.
 */
@Component
public class FederationProviderFactory {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OidcTokenClient oidcTokenClient;
    private final SamlAssertionValidator samlAssertionValidator;
    private final EidAssertionValidator eidAssertionValidator;
    private final EidArtifactResolver eidArtifactResolver;

    public FederationProviderFactory(final OidcTokenClient oidcTokenClient,
                                     final SamlAssertionValidator samlAssertionValidator,
                                     final EidAssertionValidator eidAssertionValidator,
                                     final EidArtifactResolver eidArtifactResolver) {
        this.oidcTokenClient = oidcTokenClient;
        this.samlAssertionValidator = samlAssertionValidator;
        this.eidAssertionValidator = eidAssertionValidator;
        this.eidArtifactResolver = eidArtifactResolver;
    }

    public List<IdentityProvider> build(final FederationProviderProperties properties) {
        final List<IdentityProvider> providers = new ArrayList<>();
        for (final OidcProviderConfig config : properties.getOidc()) {
            providers.add(new OidcIdentityProvider(config, oidcTokenClient, FederationProviderFactory::token));
        }
        for (final FederationProviderProperties.SocialEntry social : properties.getSocial()) {
            providers.add(new OidcIdentityProvider(socialConfig(social), oidcTokenClient, FederationProviderFactory::token));
        }
        for (final SamlProviderConfig config : properties.getSaml()) {
            providers.add(new Saml2IdentityProvider(config, samlAssertionValidator,
                    () -> "_" + token(), () -> Instant.now().toString()));
        }
        for (final EidProviderConfig config : properties.getEid()) {
            providers.add(new EidSamlIdentityProvider(config, eidAssertionValidator, eidArtifactResolver));
        }
        return providers;
    }

    /**
     * Helix IAM E8.3: builds a single runtime {@link IdentityProvider} from a stored, admin-managed
     * config (the {@code protocol} + a flat settings map persisted by the admin API). The protocol
     * selects the broker; the map supplies the protocol-specific settings. This is what lets a
     * connection created in the console become loginable on the next registry refresh, without code.
     */
    public IdentityProvider fromStored(final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored) {
        final Map<String, String> c = stored.config() == null ? Map.of() : stored.config();
        final String protocol = stored.protocol() == null ? "" : stored.protocol().toLowerCase();
        final IdentityProvider base = switch (protocol) {
            case "oidc", "social" -> new OidcIdentityProvider(oidcFromStored(stored, c), oidcTokenClient, FederationProviderFactory::token);
            case "saml", "saml2" -> new Saml2IdentityProvider(samlFromStored(stored, c), samlAssertionValidator,
                    () -> "_" + token(), () -> Instant.now().toString());
            case "eid", "digid", "eherkenning", "eidas" -> new EidSamlIdentityProvider(eidFromStored(stored, protocol, c), eidAssertionValidator, eidArtifactResolver);
            default -> throw new IllegalArgumentException("Unknown stored provider protocol: " + stored.protocol());
        };
        // Login-button branding: an explicit iconKey/logoUrl set in the console wins; otherwise infer the
        // built-in mark from the protocol/alias (so existing eID connections stored as protocol=oidc still
        // resolve to their scheme's official mark).
        final String logoUrl = blankToNull(c.get("logoUrl"));
        final String iconKey = firstNonNull(blankToNull(c.get("iconKey")),
                inferIconKey(protocol, stored.alias(), stored.displayName()));
        return new PresentedProvider(base, iconKey, logoUrl);
    }

    /** The built-in brand-mark key for a stored connection: explicit eID scheme, name/alias hint, else protocol. */
    static String inferIconKey(final String protocol, final String alias, final String displayName) {
        final String hay = ((alias == null ? "" : alias) + " " + (displayName == null ? "" : displayName)).toLowerCase();
        if ("digid".equals(protocol) || hay.contains("digid")) {
            return "digid";
        }
        if ("eherkenning".equals(protocol) || hay.contains("eherkenning")) {
            return "eherkenning";
        }
        if ("eidas".equals(protocol) || hay.contains("eidas")) {
            return "eidas";
        }
        return switch (protocol) {
            case "saml", "saml2" -> "saml";
            case "oidc", "social" -> "oidc";
            case "ldap", "ad" -> "ldap";
            default -> null;
        };
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v;
    }

    private static String firstNonNull(final String a, final String b) {
        return a != null ? a : b;
    }

    private static OidcProviderConfig oidcFromStored(
            final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored, final Map<String, String> c) {
        final String scopes = c.get("scopes");
        final List<String> scopeList = scopes == null || scopes.isBlank()
                ? List.of("openid")
                : List.of(scopes.trim().split("[\\s,]+"));
        return new OidcProviderConfig(stored.alias(), stored.displayName(), c.get("clientId"), c.get("clientSecret"),
                c.get("authorizationEndpoint"), c.get("tokenEndpoint"), c.get("jwksUri"), c.get("issuer"), scopeList);
    }

    private static SamlProviderConfig samlFromStored(
            final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored, final Map<String, String> c) {
        return new SamlProviderConfig(stored.alias(), stored.displayName(), c.get("ssoUrl"), c.get("idpEntityId"),
                c.get("spEntityId"), c.get("assertionConsumerServiceUrl"), c.get("idpSigningCertificate"),
                c.getOrDefault("emailAttribute", "email"), c.get("firstNameAttribute"), c.get("lastNameAttribute"),
                c.get("singleLogoutServiceUrl"));
    }

    private static EidProviderConfig eidFromStored(
            final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored, final String protocol,
            final Map<String, String> c) {
        final io.helixiam.authorization.federation.eid.EidScheme scheme = eidScheme(protocol, c.get("scheme"));
        final EidProviderConfig.Binding binding = "redirect".equalsIgnoreCase(c.get("binding"))
                ? EidProviderConfig.Binding.REDIRECT : EidProviderConfig.Binding.POST;
        // "artifact" = classic DigiD (back-channel resolve); default "post" = modern eID front-channel POST.
        final EidProviderConfig.ResponseBinding responseBinding = "artifact".equalsIgnoreCase(c.get("responseBinding"))
                ? EidProviderConfig.ResponseBinding.ARTIFACT : EidProviderConfig.ResponseBinding.POST;
        return new EidProviderConfig(scheme, stored.alias(), stored.displayName(), c.get("ssoUrl"),
                c.get("idpEntityId"), c.get("spEntityId"), c.get("assertionConsumerServiceUrl"),
                c.get("idpSigningCertificate"), c.get("spDecryptionPrivateKey"), c.get("spSigningPrivateKey"),
                c.get("spSigningCertificate"), c.get("minimumLoa"), c.get("subjectAttribute"), binding,
                null, responseBinding, c.get("artifactResolutionServiceUrl"), c.get("singleLogoutServiceUrl"));
    }

    private static io.helixiam.authorization.federation.eid.EidScheme eidScheme(final String protocol, final String override) {
        final String value = override == null || override.isBlank() ? protocol : override;
        return switch (value.toLowerCase()) {
            case "eidas" -> io.helixiam.authorization.federation.eid.EidScheme.EIDAS;
            case "eherkenning" -> io.helixiam.authorization.federation.eid.EidScheme.EHERKENNING;
            case "digid", "eid" -> io.helixiam.authorization.federation.eid.EidScheme.DIGID;
            default -> throw new IllegalArgumentException("Unknown eID scheme: " + value);
        };
    }

    private static OidcProviderConfig socialConfig(final FederationProviderProperties.SocialEntry entry) {
        final String provider = entry.provider() == null ? "" : entry.provider().toLowerCase();
        return switch (provider) {
            case "google" -> SocialProviders.google(entry.clientId(), entry.clientSecret());
            case "microsoft" -> SocialProviders.microsoft(entry.clientId(), entry.clientSecret(),
                    entry.tenant() == null || entry.tenant().isBlank() ? "common" : entry.tenant());
            default -> throw new IllegalArgumentException("Unknown social login preset: " + entry.provider());
        };
    }

    private static String token() {
        final byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
