package group.mfnr.authorization.federation.eid;

/**
 * Helix IAM E6: resolves a SAML 2.0 artifact ({@code SAMLart}) over the back-channel for classic DigiD
 * ("Koppelvlak SAML"). The IdP returns only a short artifact reference on the front channel; the SP
 * must POST a signed {@code <samlp:ArtifactResolve>} (wrapped in a SOAP envelope) to the IdP's Artifact
 * Resolution Service (ARS) over a mutually-authenticated TLS back-channel and read the signed
 * {@code <samlp:ArtifactResponse>}, which carries the actual {@code <samlp:Response>}.
 *
 * <p>Behind a seam so the eID connector's callback routing stays unit-testable; the production impl
 * ({@link OpenSamlEidArtifactResolver}) is backed by OpenSAML + a TLS HTTP client. The returned value
 * is the base64 of the resolved {@code <samlp:Response>}, fed straight into the existing
 * {@link EidAssertionValidator} so signature / decryption / LoA checks are identical to the POST path.
 */
public interface EidArtifactResolver {

    /**
     * @param config  the eID provider config (ARS URL + SP signing key/cert for the signed ArtifactResolve
     *                and TLS client auth + IdP cert for verifying the ArtifactResponse)
     * @param samlArt the {@code SAMLart} the IdP returned on the front channel
     * @return the base64-encoded {@code <samlp:Response>} extracted from the {@code ArtifactResponse}
     * @throws IllegalStateException if resolution fails (transport, SOAP fault, signature, or no Response)
     */
    String resolve(EidProviderConfig config, String samlArt);
}
