package group.mfnr.authorization.federation;

import group.mfnr.authorization.federation.spi.BrokeredIdentity;

import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E5.1: the broker's seam onto the identity domain (the subscriber, over AMQP, in prod).
 * Keeps {@link IdentityBroker} pure + unit-testable. Resolves existing federated links + local users,
 * creates links, and JIT-provisions new local users from a brokered identity.
 */
public interface FederatedIdentityStore {

    /** The local user id previously linked to this (idpAlias, externalSubject), if any. */
    Optional<String> findLinkedUser(String idpAlias, String externalSubject);

    /** A local user with this email, if any (used only for verified-email account linking). */
    Optional<String> findUserByEmail(String email);

    /** Record a federated link from an external subject to a local user. */
    void link(String idpAlias, String externalSubject, String userId);

    /** Just-in-time provision a new local user from the brokered identity + mapped attributes; returns its id. */
    String provisionUser(BrokeredIdentity identity, Map<String, String> attributes);
}
