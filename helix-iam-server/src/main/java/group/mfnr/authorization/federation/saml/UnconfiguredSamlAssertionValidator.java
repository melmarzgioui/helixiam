package group.mfnr.authorization.federation.saml;


/**
 * Helix IAM E5.2: fail-closed default {@link SamlAssertionValidator}. SAML Response validation
 * (signature, conditions, audience, replay) must be done by the OpenSAML-backed validator
 * (spring-security-saml2-service-provider) — a follow-up that requires the OpenSAML dependency and
 * a live IdP to validate against. Until that bean is present this default REJECTS every assertion,
 * so the SAML broker fails closed rather than ever trusting an unvalidated response.
 */
public class UnconfiguredSamlAssertionValidator implements SamlAssertionValidator {

    @Override
    public ValidatedAssertion validate(final SamlProviderConfig config, final String samlResponseBase64,
                                       final String expectedRelayState) {
        throw new IllegalStateException("SAML assertion validation is not configured for provider "
                + config.alias() + " — install the OpenSAML-backed SamlAssertionValidator (E5.2 follow-up)");
    }
}
