package io.helixiam.authorization.amqp.scim;


import java.util.List;

/**
 * Helix IAM B7: the admin API's seam onto the identity-domain store (owned by the subscriber) for
 * per-realm outbound SCIM provisioning targets. JSON-marshalled two-copy DTOs, like the other config
 * exchanges. The provisioning dispatcher reads {@code active} to load the targets to push user changes to.
 */
public interface ScimTargetConfigPublisher {

    String EXCHANGE_AUTHORIZATION_SCIM = "exchange-authorization-scim-provisioning";
    String SCIM_LIST = "authorization.scim.targets.list";
    String SCIM_ACTIVE = "authorization.scim.targets.active";
    String SCIM_SAVE = "authorization.scim.targets.save";
    String SCIM_DELETE = "authorization.scim.targets.delete";

    /** All SCIM targets for a realm (console list). */
    List<ScimTargetDto> list(final String realmId);

    /** Enabled SCIM targets for a realm — what the provisioning dispatcher pushes user changes to. */
    List<ScimTargetDto> active(final String realmId);

    /** Create or update a target; returns the persisted state. */
    ScimTargetDto save(final ScimTargetDto target);

    /** Remove a target; {@code false} if it did not exist. */
    Boolean delete(final ScimTargetRef ref);
}
