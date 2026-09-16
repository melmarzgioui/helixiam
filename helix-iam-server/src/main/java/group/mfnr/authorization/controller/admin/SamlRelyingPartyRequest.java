package group.mfnr.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import group.mfnr.authorization.amqp.saml.SamlSpOptions;
import jakarta.validation.constraints.NotBlank;

/**
 * Helix IAM: create/update request body for a SAML2 relying party (service provider). {@code options}
 * carries the WSO2-class advanced SAML toggles (null = all IdP defaults, back-compat).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SamlRelyingPartyRequest(@NotBlank(message = "Entity ID is required.") String entityId,
                                      @NotBlank(message = "Assertion Consumer Service URL is required.") String assertionConsumerServiceUrl,
                                      String defaultAuthnContextClassRef, String singleLogoutServiceUrl,
                                      String signingCertificate, Boolean enabled, String applicationId,
                                      SamlSpOptions options) {
}
