package io.helixiam.authorization.amqp.saml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM: a per-realm SAML2 relying party (SP) as it crosses AMQP and the admin API. Publisher-side
 * copy of the two-copy DTO. Mirrors the federation {@code IdentityProviderConfig}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SamlRelyingPartyConfig(String realmId, String entityId, String assertionConsumerServiceUrl,
                                     String defaultAuthnContextClassRef, String singleLogoutServiceUrl,
                                     String signingCertificate, boolean enabled, String applicationId,
                                     SamlSpOptions options) {

    /** The advanced options, never null — falls back to all-defaults for SPs saved before they existed. */
    public SamlSpOptions optionsOrDefaults() {
        return options == null ? SamlSpOptions.defaults() : options;
    }
}
