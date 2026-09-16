package io.helixiam.authorization.security.fapi;

import java.util.HashMap;
import java.util.Map;

/**
 * Helix IAM B11 (FAPI / RFC 8705): builds the access token's {@code cnf} (confirmation) claim that binds
 * the token to a client certificate via {@code x5t#S256}. Coexists with a DPoP {@code jkt} confirmation
 * (RFC 9449) when both are present. Always returns a MUTABLE map — the SAS Jackson allowlist rejects
 * immutable collections (Map.of/List.of) inside OAuth2 token claims.
 */
public final class MtlsConfirmation {

    /** The RFC 8705 confirmation method key: the certificate's SHA-256 thumbprint. */
    public static final String X5T_S256 = "x5t#S256";

    private MtlsConfirmation() {
    }

    /**
     * Returns a mutable {@code cnf} map containing {@code x5t#S256=thumbprint}, preserving every entry of
     * an existing {@code cnf} (e.g. a DPoP {@code jkt}). {@code existingCnf} may be null or any Map.
     */
    public static Map<String, Object> mergeX5t(final Object existingCnf, final String thumbprint) {
        final Map<String, Object> cnf = new HashMap<>();
        if (existingCnf instanceof Map<?, ?> existing) {
            existing.forEach((k, v) -> cnf.put(String.valueOf(k), v));
        }
        cnf.put(X5T_S256, thumbprint);
        return cnf;
    }
}
