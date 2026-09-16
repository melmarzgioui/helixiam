package io.helixiam.authorization.amqp.saml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM: the WSO2-class advanced SAML2 options for a relying party (service provider), carried as a
 * nested block on {@link SamlRelyingPartyConfig}. All fields are nullable; {@code null} = "use the IdP
 * default" (the {@code *OrDefault()} accessors apply them), so an SP configured before these options
 * existed behaves exactly as before. Publisher-side copy of the two-copy DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SamlSpOptions(
        Boolean signAssertion,
        Boolean signResponse,
        Boolean wantAuthnRequestsSigned,
        Boolean wantLogoutRequestsSigned,
        Boolean encryptAssertion,
        String encryptionCertificate,
        String signatureAlgorithm,
        String digestAlgorithm,
        String nameIdFormat,
        Boolean includeAttributes,
        List<String> additionalAcsUrls,
        List<String> extraAudiences,
        List<String> extraRecipients,
        Boolean backChannelSloEnabled,
        Boolean idpInitiatedSsoEnabled,
        Integer assertionLifetimeSeconds) {

    /** The WSO2-parity default NameID format when an SP doesn't pin one. */
    public static final String DEFAULT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    /** A fully-default options block (every field null → every accessor returns its default). */
    public static SamlSpOptions defaults() {
        return new SamlSpOptions(null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null);
    }

    public boolean signAssertionOrDefault() {
        return signAssertion == null || signAssertion;          // default ON (today's behaviour)
    }

    public boolean signResponseOrDefault() {
        return Boolean.TRUE.equals(signResponse);               // default OFF
    }

    public boolean wantAuthnRequestsSignedOrDefault() {
        return Boolean.TRUE.equals(wantAuthnRequestsSigned);    // default OFF (no behaviour change)
    }

    public boolean wantLogoutRequestsSignedOrDefault() {
        return wantLogoutRequestsSigned == null || wantLogoutRequestsSigned; // default ON
    }

    public boolean encryptAssertionOrDefault() {
        return Boolean.TRUE.equals(encryptAssertion);           // default OFF
    }

    public boolean includeAttributesOrDefault() {
        return includeAttributes == null || includeAttributes;  // default ON
    }

    public boolean backChannelSloEnabledOrDefault() {
        return Boolean.TRUE.equals(backChannelSloEnabled);
    }

    public boolean idpInitiatedSsoEnabledOrDefault() {
        return Boolean.TRUE.equals(idpInitiatedSsoEnabled);
    }

    public String nameIdFormatOrDefault() {
        return blank(nameIdFormat) ? DEFAULT_NAME_ID_FORMAT : nameIdFormat;
    }

    public String signatureAlgorithmOrDefault() {
        return blank(signatureAlgorithm) ? "RSA_SHA256" : signatureAlgorithm;
    }

    public String digestAlgorithmOrDefault() {
        return blank(digestAlgorithm) ? "SHA256" : digestAlgorithm;
    }

    public int assertionLifetimeSecondsOrDefault() {
        return assertionLifetimeSeconds == null || assertionLifetimeSeconds <= 0 ? 300 : assertionLifetimeSeconds;
    }

    public List<String> additionalAcsUrlsOrEmpty() {
        return additionalAcsUrls == null ? List.of() : additionalAcsUrls;
    }

    public List<String> extraAudiencesOrEmpty() {
        return extraAudiences == null ? List.of() : extraAudiences;
    }

    public List<String> extraRecipientsOrEmpty() {
        return extraRecipients == null ? List.of() : extraRecipients;
    }

    private static boolean blank(final String s) {
        return s == null || s.isBlank();
    }
}
