package group.mfnr.authorization.idp.saml;

/**
 * Helix IAM E7.1: configuration for Helix acting as a SAML2 <b>Identity Provider</b> — the entity id
 * it asserts under and the key/cert it signs assertions with (sourced from the realm's KMS in prod).
 *
 * @param idpEntityId          Helix's IdP entity id (the assertion Issuer)
 * @param signingCertificate   the IdP signing certificate (PEM), published in IdP metadata
 * @param signingPrivateKey    the IdP signing private key (PEM, PKCS#8)
 */
public record SamlIdpConfig(String idpEntityId, String signingCertificate, String signingPrivateKey) {
}
