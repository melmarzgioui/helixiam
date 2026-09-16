package group.mfnr.authorization.security.mapper;

import group.mfnr.authorization.amqp.mapper.ProtocolMapperDto;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM (Wave 3): resolves a client's protocol mappers into a set of token claims, given the
 * authenticated user's OIDC claim profile and roles. Pure (no I/O) so the token-issuance customizer can
 * apply it inline. {@code USER_ATTRIBUTE} maps {@code profile[source] → claimName}; {@code HARDCODED} emits
 * the literal {@code source}; {@code USER_ROLE} emits the principal's roles as a list claim. Mappers gate on
 * the per-token-type flags.
 */
public final class ProtocolMapperResolver {

    private ProtocolMapperResolver() {
    }

    /**
     * The claims a client's mappers contribute to one token. {@code accessToken=true} resolves the
     * access-token set; {@code false} resolves the ID-token set. {@code roles} are the principal's effective
     * roles (used by {@code USER_ROLE} mappers).
     */
    public static Map<String, Object> claimsForTokenType(final List<ProtocolMapperDto> mappers,
                                                          final Map<String, String> profile,
                                                          final Set<String> roles,
                                                          final boolean accessToken) {
        final Map<String, Object> out = new LinkedHashMap<>();
        if (mappers == null) {
            return out;
        }
        for (final ProtocolMapperDto m : mappers) {
            final boolean include = accessToken ? m.addToAccessToken() : m.addToIdToken();
            if (!include || m.claimName() == null || m.claimName().isBlank()) {
                continue;
            }
            if ("USER_ROLE".equals(m.mapperType())) {
                if (roles != null && !roles.isEmpty()) {
                    // Mutable ArrayList (not .toList()) — SAS's authorization (de)serialization allowlist
                    // rejects immutable collections, which would break logout/refresh/introspect.
                    out.put(m.claimName(), new java.util.ArrayList<>(roles.stream().sorted().toList()));
                }
                continue;
            }
            final String value = "HARDCODED".equals(m.mapperType())
                    ? m.source()
                    : (profile == null ? null : profile.get(m.source()));
            if (value != null && !value.isBlank()) {
                out.put(m.claimName(), value);
            }
        }
        return out;
    }
}
