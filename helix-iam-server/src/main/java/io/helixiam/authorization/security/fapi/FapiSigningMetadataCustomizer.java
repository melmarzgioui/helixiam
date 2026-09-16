package io.helixiam.authorization.security.fapi;

import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Helix IAM A2 (FAPI2): advertise <b>PS256</b> (RSASSA-PSS) as a supported signing algorithm in the OIDC
 * discovery document, alongside the default RS256.
 *
 * <p>FAPI2 forbids RS256 for signatures, so a FAPI client must be able to request PS256-signed id_tokens.
 * The realm's active RSA key material is now published for both RS256 and PS256 (see
 * {@code RealmJwkSource}), so PS256 is genuinely available; this customizer makes the discovery document
 * reflect that. RS256 stays the default for backward compatibility — this only <i>adds</i> PS256 to the
 * advertised set. Additive and off the token hot path.
 */
public final class FapiSigningMetadataCustomizer implements Consumer<OidcProviderConfiguration.Builder> {

    private static final String CLAIM = "id_token_signing_alg_values_supported";

    @Override
    public void accept(final OidcProviderConfiguration.Builder builder) {
        builder.claims(claims -> {
            final Set<String> algs = new LinkedHashSet<>();
            final Object existing = claims.get(CLAIM);
            if (existing instanceof Collection<?> collection) {
                for (final Object alg : collection) {
                    algs.add(String.valueOf(alg));
                }
            } else {
                algs.add("RS256");
            }
            algs.add("PS256");
            // Store a mutable-safe copy (SAS's Jackson allowlist rejects immutable List.of/.copyOf).
            claims.put(CLAIM, new java.util.ArrayList<>(algs));
        });
    }
}
