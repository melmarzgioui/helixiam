package io.helixiam.authorization.amqp.federation;


import java.util.List;

/**
 * Helix IAM E8.2: the admin API's seam onto the identity-domain store (owned by the subscriber) for
 * managing per-realm identity-provider configs. JSON-marshalled, two-copy DTOs, like the other
 * federation exchanges. The federation registry (E8.3) reads the same store to register providers.
 */
public interface IdentityProviderConfigPublisher {

    String EXCHANGE_AUTHORIZATION_FEDERATION_CONFIG = "exchange-authorization-federation-config";
    String FEDERATION_IDP_SAVE = "authorization.federation.idp.save";
    String FEDERATION_IDP_LIST = "authorization.federation.idp.list";
    String FEDERATION_IDP_GET = "authorization.federation.idp.get";
    String FEDERATION_IDP_DELETE = "authorization.federation.idp.delete";

    /** Create or update a config; returns the persisted state. */
    IdentityProviderConfig save(final IdentityProviderConfig config);

    /** All identity-provider configs for a realm. */
    List<IdentityProviderConfig> list(final String realmId);

    /** A single config, or {@code null} if none. */
    IdentityProviderConfig get(final IdentityProviderRef ref);

    /** Remove a config; {@code false} if it did not exist. */
    Boolean delete(final IdentityProviderRef ref);
}
