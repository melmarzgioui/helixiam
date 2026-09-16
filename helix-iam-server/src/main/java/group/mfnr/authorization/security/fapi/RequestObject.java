package group.mfnr.authorization.security.fapi;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM B11 (FAPI / RFC 9101 — JWT-Secured Authorization Request, "JAR"): a Request Object is a JWT
 * whose claims ARE the authorization request parameters. This projects a (signature-verified) Request
 * Object's claims onto the OAuth parameter map the authorization endpoint consumes, dropping the
 * JWT-registered claims that are not request parameters. Pure; signature verification against the client's
 * JWKS + the servlet rewrite are the surrounding glue.
 */
public final class RequestObject {

    /** JWT-registered claims that are envelope metadata, not OAuth authorization-request parameters. */
    private static final Set<String> JWT_REGISTERED = Set.of("iss", "aud", "exp", "iat", "nbf", "jti");

    private RequestObject() {
    }

    /** The OAuth authorization-request parameters carried by a Request Object (registered JWT claims removed). */
    public static Map<String, String> toParameters(final JWTClaimsSet claims) {
        final Map<String, String> params = new LinkedHashMap<>();
        if (claims == null) {
            return params;
        }
        claims.getClaims().forEach((name, value) -> {
            if (value != null && !JWT_REGISTERED.contains(name)) {
                params.put(name, String.valueOf(value));
            }
        });
        return params;
    }
}
