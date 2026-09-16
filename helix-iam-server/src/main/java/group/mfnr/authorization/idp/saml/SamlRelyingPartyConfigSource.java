package group.mfnr.authorization.idp.saml;

import group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfig;

import java.util.List;

/**
 * Helix IAM: the seam the SAML IdP reads stored relying parties from. Backed by the admin/config store
 * over AMQP in production; a simple stub in tests. Keeping it an interface lets the IdP resolve the
 * calling SP from the DB the admin console writes to, without coupling to the transport.
 */
@FunctionalInterface
public interface SamlRelyingPartyConfigSource {

    /** The persisted SAML relying parties for a realm. */
    List<SamlRelyingPartyConfig> load(String realmId);
}
